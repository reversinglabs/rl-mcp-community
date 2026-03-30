import asyncio
import json
import logging
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from src.server import (
    REPORTS_DIR,
    RL_PROTECT_BIN,
    SCAN_TIMEOUT,
    get_auth_args,
    get_optional_args,
    mcp,
)

logger = logging.getLogger(__name__)


def _make_report_id(name: str) -> str:
    """Append a random suffix to the LLM-suggested name to avoid collisions."""
    suffix = secrets.token_hex(4)
    return f"{name}-{suffix}"


def _run_scan(
    target: str,
    *,
    report_name: str,
    profile: str | None = None,
    extra_args: list[str] | None = None,
) -> tuple[dict, str]:
    """Run rl-protect scan. Returns (parsed_report, report_id)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

    target = ",".join(p.strip() for p in target.split(","))

    try:
        cmd = [
            RL_PROTECT_BIN, "scan", target,
            "--save-report", report_path,
            "--return-status",
            "--fail-only",
            "--concise",
        ]
        cmd += get_auth_args()
        cmd += get_optional_args(profile_override=profile)
        if extra_args:
            cmd += extra_args

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)  # noqa: S603
        logger.debug("rl-protect stdout: %s", result.stdout)
        logger.debug("rl-protect stderr: %s", result.stderr)

        report_file = Path(report_path)
        report_content = report_file.read_text() if report_file.exists() else ""

        if not report_content.strip():
            raise RuntimeError(
                f"rl-protect produced an empty report (exit code {result.returncode}). "
                f"stderr: {result.stderr}"
            )

        report = json.loads(report_content)

        report_id = _make_report_id(report_name)
        reports_dir = Path(REPORTS_DIR)
        reports_dir.mkdir(parents=True, exist_ok=True)
        dest = reports_dir / f"{report_id}.json"
        shutil.copy2(report_path, dest)

        return report, report_id
    finally:
        Path(report_path).unlink(missing_ok=True)


_ASSESSMENTS = ["secrets", "licenses", "vulnerabilities", "hardening", "tampering", "malware", "repository"]


def _worst_status(assessment: dict) -> str:
    statuses = [assessment.get(k, {}).get("status", "pass") for k in _ASSESSMENTS]
    if "fail" in statuses:
        return "fail"
    if "warning" in statuses:
        return "warning"
    return "pass"


_ASSESSMENT_PRIORITY = ["malware", "tampering", "vulnerabilities", "secrets", "hardening", "licenses"]


def _worst_label(assessment: dict) -> str:
    ws = _worst_status(assessment)
    repo = assessment.get("repository", {})
    if repo.get("status", "pass") != "pass":
        return repo.get("label", "")
    for k in _ASSESSMENT_PRIORITY:
        if assessment.get(k, {}).get("status") == ws:
            return assessment.get(k, {}).get("label", "")
    return ""


def _format_result(report: dict, report_id: str) -> str:
    """Return a compact scan result: one row per package, summary counts, report_id."""
    analysis = report.get("analysis", {})
    report_data = analysis.get("report", {})

    packages = []
    n_reject = n_warn = 0
    for pkg in report_data.get("packages", []):
        rec = pkg.get("analysis", {}).get("recommendation", "APPROVE")
        assessment = pkg.get("analysis", {}).get("assessment", {})
        ws = _worst_status(assessment)
        packages.append({
            "purl": pkg.get("purl", ""),
            "recommendation": rec,
            "worst_status": ws,
            "worst_label": _worst_label(assessment),
        })
        if rec == "REJECT":
            n_reject += 1
        elif ws in ("warning", "fail"):
            n_warn += 1

    total = len(packages)
    return json.dumps({
        "report_id": report_id,
        "metadata": {
            "timestamp": analysis.get("timestamp"),
            "duration": analysis.get("duration"),
            "profile": analysis.get("profile", {}).get("name"),
        },
        "summary": {
            "reject": n_reject,
            "warn": n_warn,
            "pass": total - n_reject - n_warn,
            "total": total,
        },
        "packages": packages,
        "errors": report_data.get("errors", []),
    })


@mcp.tool()
async def rl_protect_scan(
    purls: str,
    report_name: str,
    profile: str | None = None,
    check_deps: str | None = None,
) -> str:
    """Scan open source packages for supply chain risk using ReversingLabs Spectra Assure.

    Call this tool before adding, recommending, or importing any open source package.
    A REJECT result means the package has known security issues and should not be used.

    Accepts a comma-separated list of package PURLs. Version is optional; omitting it
    scans the latest version.
    Examples:
      "pkg:npm/react@19.1.5,pkg:pypi/requests@2.32.3"
      "pkg:npm/express"
      "pkg:pypi/flask@3.1.2,pkg:pypi/requests"

    The report_name you provide is used to save the full report for later queries
    with rl_protect_summarize, rl_protect_interpret, or rl_protect_diff_behavior.
    A random suffix is appended automatically to avoid collisions between concurrent
    sessions. The actual report_id is returned in the response.

    For version updates, scan both old and new versions together and use
    rl_protect_diff_behavior to compare.

    Returns a compact JSON summary — use rl_protect_summarize(report_id) to drill
    into any package that needs investigation:
      report_id: unique identifier for querying this report later
      metadata: {timestamp, duration, profile}
      summary: {reject, warn, pass, total}
      packages[]: each with {purl, recommendation (APPROVE/REJECT),
        worst_status (pass/warning/fail), worst_label (human-readable worst check)}
      errors[]: packages that could not be scanned

    DISPLAY INSTRUCTIONS — you MUST render the report exactly as follows.
    Do NOT omit or substitute the icons. Do NOT replace icons with words like
    "PASS", "WARN", or "FAIL". Use the exact Unicode characters shown below.

    Icons (mandatory):
      ✅  worst_status == "pass"   (and recommendation == "APPROVE")
      ⚠️  worst_status == "warning" or "fail"  (but recommendation == "APPROVE")
      ❌  recommendation == "REJECT"

    Status line (pick exactly one):
      ❌ Build blocked — {N} dependenc(y/ies) must be fixed     ← any REJECT
      ⚠️ Build warning — {N} dependenc(y/ies) require review    ← warn only, no REJECT
      ✅ All clear — no issues detected                         ← all APPROVE + pass

    Required format:

      ## `rl-protect` scan report

      **Target:** `{purls}` · {N} dependencies scanned

      ---

      ### ✅/⚠️/❌ {status_line}

      {one-sentence summary of the most critical finding, or "All dependencies passed."}

      ---

      ### Results
      *(Omit this section entirely if all dependencies passed.)*

      | Dependency | Version | Status | Issues |
      |---|---|---|---|
      | {name} | {version} | ✅ or ⚠️ or ❌ | {worst_label, or "—" if none} |

      ---

      ❌ **REJECT** {N} · ⚠️ **WARN** {N} · ✅ **PASS** {N}

      > For full assessment detail on any package, call rl_protect_summarize("{report_id}").

    Args:
        purls: Comma-separated package PURLs to scan.
        report_name: A descriptive name for this report (e.g. "express-scan", "deps-update").
        profile: Scanning profile keyword (minimum, baseline, hardened) or path.
        check_deps: Comma-separated dependency scopes to scan. Must include release or develop.
            Values: release, develop, optional, transitive. Default (omit): release only.
            Example: "release,develop" or "release,develop,optional,transitive".
    """
    extra_args = ["--check-deps", check_deps] if check_deps else None
    report, report_id = await asyncio.to_thread(
        _run_scan, purls, report_name=report_name, profile=profile, extra_args=extra_args,
    )
    return _format_result(report, report_id)


@mcp.tool()
async def rl_protect_scan_manifest(
    manifest_path: str,
    report_name: str,
    profile: str | None = None,
    check_deps: str | None = None,
) -> str:
    """Scan a manifest or lock file for supply chain risk using ReversingLabs Spectra Assure.

    Use this tool to scan project dependency files (package.json, requirements.txt,
    pyproject.toml, setup.cfg, Gemfile, gemspec) that are accessible inside the
    container.

    IMPORTANT — Volume mount required: The MCP server runs inside a Docker container
    and cannot access host files directly. The user must mount their project directory
    when starting the container:

      docker run --rm -i -e RL_TOKEN=... -v /path/to/project:/project rl-mcp-community

    Then pass container-relative paths like "/project/package.json".

    Returns the same compact JSON structure as rl_protect_scan — use
    rl_protect_summarize(report_id) to drill into any package that needs investigation:
      report_id: unique identifier for querying this report later
      metadata: {timestamp, duration, profile}
      summary: {reject, warn, pass, total}
      packages[]: each with {purl, recommendation (APPROVE/REJECT),
        worst_status (pass/warning/fail), worst_label (human-readable worst check)}
      errors[]: packages that could not be scanned

    DISPLAY INSTRUCTIONS — you MUST render the report exactly as follows.
    Do NOT omit or substitute the icons. Do NOT replace icons with words like
    "PASS", "WARN", or "FAIL". Use the exact Unicode characters shown below.

    Icons (mandatory):
      ✅  worst_status == "pass"   (and recommendation == "APPROVE")
      ⚠️  worst_status == "warning" or "fail"  (but recommendation == "APPROVE")
      ❌  recommendation == "REJECT"

    Status line (pick exactly one):
      ❌ Build blocked — {N} dependenc(y/ies) must be fixed     ← any REJECT
      ⚠️ Build warning — {N} dependenc(y/ies) require review    ← warn only, no REJECT
      ✅ All clear — no issues detected                         ← all APPROVE + pass

    Required format:

      ## `rl-protect` scan report

      **Manifest:** `{manifest_path}` · {N} dependencies scanned

      ---

      ### ✅/⚠️/❌ {status_line}

      {one-sentence summary of the most critical finding, or "All dependencies passed."}

      ---

      ### Results
      *(Omit this section entirely if all dependencies passed.)*

      | Dependency | Version | Status | Issues |
      |---|---|---|---|
      | {name} | {version} | ✅ or ⚠️ or ❌ | {worst_label, or "—" if none} |

      ---

      ❌ **REJECT** {N} · ⚠️ **WARN** {N} · ✅ **PASS** {N}

      > For full assessment detail on any package, call rl_protect_summarize("{report_id}").

    Args:
        manifest_path: Container-relative path to a manifest or lock file (e.g. "/project/package.json").
        report_name: A descriptive name for this report (e.g. "project-deps", "lockfile-audit").
        profile: Scanning profile keyword (minimum, baseline, hardened) or path.
        check_deps: Comma-separated dependency scopes to scan. Must include release or develop.
            Values: release, develop, optional, transitive. Default (omit): release only.
            Example: "release,develop" or "release,develop,optional,transitive".
    """
    extra_args = ["--check-deps", check_deps] if check_deps else None
    report, report_id = await asyncio.to_thread(
        _run_scan, manifest_path, report_name=report_name, profile=profile, extra_args=extra_args,
    )
    return _format_result(report, report_id)
