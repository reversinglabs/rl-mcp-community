import importlib.util
import json
import logging
from pathlib import Path

from src.server import REPORTS_DIR, SCRIPTS_DIR, mcp

logger = logging.getLogger(__name__)

_ASSESSMENTS = ["secrets", "licenses", "vulnerabilities", "hardening", "tampering", "malware", "repository"]


def _load_script(name: str):
    """Load a script from SCRIPTS_DIR as a module by file path."""
    path = Path(SCRIPTS_DIR) / name
    if not path.exists():
        raise FileNotFoundError(f"Script not found: {path}")
    module_name = name.replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _report_path(report_id: str) -> Path:
    path = Path(REPORTS_DIR) / f"{report_id}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"Report '{report_id}' not found. Run rl_protect_scan() first — "
            f"the report_id is returned in its response."
        )
    return path


def _pkg_has_issues(pkg: dict) -> bool:
    if pkg.get("recommendation") == "REJECT":
        return True
    assessment = pkg.get("assessment", {})
    return any(
        assessment.get(k, {}).get("status") in ("warning", "fail")
        for k in _ASSESSMENTS
    )


@mcp.tool()
async def rl_protect_summarize(report_id: str) -> str:
    """Summarize packages with issues from a saved rl-protect report.

    Returns full assessment detail for packages that have REJECT recommendation
    or any non-pass check. Passing packages are omitted — use the scan response
    for the full package list.

    Returns JSON with:
      packages[]: issue packages only, each with purl, recommendation, report_url,
        has_override, and assessment (object keyed by check name — secrets, licenses,
        vulnerabilities, hardening, tampering, malware, repository — each with status and label;
        overridden checks include an override object with to_status, author, date,
        and reason)
      summary: {reject, warn, pass, total} — counts over the full scan, not just
        the filtered packages list
      errors[]: packages that could not be scanned

    Display instructions — present results using the rl_protect_scan display
    format: status line, results table, and per-package issue detail sections.

    Args:
        report_id: The report_id returned by rl_protect_scan().
    """
    s = _load_script("summarize.py")
    path = _report_path(report_id)
    report = s.load_report(path)
    packages = s.get_packages(report)
    errors = s.get_errors(report)

    n_reject = sum(1 for p in packages if p.get("analysis", {}).get("recommendation") == "REJECT")
    n_warn = sum(
        1 for p in packages
        if p.get("analysis", {}).get("recommendation") == "APPROVE"
        and any(
            p.get("analysis", {}).get("assessment", {}).get(k, {}).get("status") in ("warning", "fail")
            for k in _ASSESSMENTS
        )
    )
    n_pass = len(packages) - n_reject - n_warn

    formatted = [s.format_package_json(p) for p in packages]
    return json.dumps({
        "packages": [p for p in formatted if _pkg_has_issues(p)],
        "errors": s.format_errors_json(errors),
        "summary": {"reject": n_reject, "warn": n_warn, "pass": n_pass, "total": len(packages)},
    })


@mcp.tool()
async def rl_protect_interpret(report_id: str, task: str, package: str | None = None) -> str:
    """Extract a specific slice of a saved rl-protect report as structured JSON.

    Available tasks:
      - vulnerabilities: CVEs with CVSS scores, severity, and exploit flags
      - indicators: Behavior indicators, file classifications, and policy violations
      - malware: Malicious/suspicious files, malware/tampering assessments, governance blocks
      - overrides: Full audit trail for assessment and policy overrides
      - governance: Governance allow/block decisions
      - dependencies: Direct dependencies with scan status and worst assessment
      - errors: Packages that could not be scanned

    Display instructions — present results in clear tables grouped by package.
    Use status icons (pass=✅, warning=⚠️, fail=❌) and recommendation icons
    (APPROVE=🟢, REJECT=🔴). For vulnerabilities, include CVSS severity labels.

    Args:
        report_id: The report_id returned by rl_protect_scan().
        task: One of: vulnerabilities, indicators, malware, overrides, governance, dependencies, errors.
        package: Optional PURL substring to filter results to a specific package.
    """
    valid_tasks = {"vulnerabilities", "indicators", "malware", "overrides", "governance", "dependencies", "errors"}
    if task not in valid_tasks:
        raise ValueError(f"Invalid task '{task}'. Must be one of: {', '.join(sorted(valid_tasks))}")

    s = _load_script("interpret.py")
    path = _report_path(report_id)
    report = s.load_report(path)

    if task == "errors":
        return json.dumps(s.task_errors_json(report))

    packages = s.get_packages(report)
    packages = s.filter_packages(packages, package or "")

    if not packages:
        msg = "No packages found" + (f" matching '{package}'" if package else "") + "."
        return json.dumps({"task": task, "exit_code": 0, "packages": [], "message": msg})

    return json.dumps(s.TASKS_JSON[task](packages))


@mcp.tool()
async def rl_protect_diff_behavior(
    package: str,
    report_id: str | None = None,
    old_report_id: str | None = None,
    new_report_id: str | None = None,
    old_version: str | None = None,
    new_version: str | None = None,
    reverse: bool = False,
) -> str:
    """Compare behaviors between two versions of the same package as structured JSON.

    Detects suspicious changes that may indicate supply chain tampering.

    Returns JSON with:
      old/new: {purl, recommendation}
      recommendation_changed: boolean
      new_risks: boolean — true if any regressions, new malware, CVEs, or violations
      assessment_changes[]: {assessment, old_status, new_status, old_label, new_label, direction}
      policy_violation_changes: {added[], removed[], changed[]}
      indicator_changes: {added[], removed[], changed[]}
      classification_changes: {added[], removed[]}
      vulnerability_changes: {added[], fixed[]}
      exit_code: 0 or 1

    Usage patterns:
      1. Single report with both versions scanned together:
         rl_protect_diff_behavior(package="express", report_id="my-report")
      2. Two separate reports:
         rl_protect_diff_behavior(package="express",
                              old_report_id="old-scan", new_report_id="new-scan")
      3. Use reverse=True when downgrading to an older version.

    Display instructions — present the diff with clear [+] added / [-] removed /
    [~] changed sections. Use ⬆ REGRESSION / ⬇ improved for assessment changes.
    Highlight new_risks=true prominently with ⚠. Show a summary line at the end.

    Args:
        package: Package name to compare (substring match, case-insensitive).
        report_id: The report_id returned by rl_protect_scan() (must contain both versions).
        old_report_id: Report ID for the old version (use with new_report_id).
        new_report_id: Report ID for the new version (use with old_report_id).
        old_version: Pin a specific old version when more than two are present.
        new_version: Pin a specific new version when more than two are present.
        reverse: Swap old and new (use when downgrading).
    """
    db = _load_script("diff-behavior.py")

    if report_id:
        report = db.load_report(_report_path(report_id))
        old_packages = db.get_packages(report)
        new_packages = old_packages
        single_report = True
    elif old_report_id and new_report_id:
        old_packages = db.get_packages(db.load_report(_report_path(old_report_id)))
        new_packages = db.get_packages(db.load_report(_report_path(new_report_id)))
        single_report = False
    else:
        raise ValueError(
            "Provide either report_id (single report with both versions) "
            "or both old_report_id and new_report_id."
        )

    old_pkg, new_pkg = db.select_versions(
        old_packages, new_packages, package,
        old_version or "", new_version or "", single_report,
    )

    if reverse:
        old_pkg, new_pkg = new_pkg, old_pkg

    return json.dumps(db.diff_to_json(old_pkg, new_pkg))
