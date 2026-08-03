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


def _normalize_purls(purls: str) -> str:
    """Strip whitespace around commas in a PURL list (e.g. 'a, b' → 'a,b')."""
    return ",".join(p.strip() for p in purls.split(","))


def _split_csv(value: str | None) -> list[str]:
    """Split a comma-separated input into values, dropping whitespace and blanks."""
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _target_args(
    *,
    target_python: str | None = None,
    target_os: str | None = None,
    target_arch: str | None = None,
    target_libc: str | None = None,
    target_platform: str | None = None,
    target_implementation: str | None = None,
    target_abi: str | None = None,
) -> list[str]:
    """Build the rl-protect artifact selection flags.

    Artifact selection pins the scan to the artifact that would be installed on a
    specific platform, instead of assessing the package as a whole.  It currently
    applies to PyPI packages only.

    rl-protect enforces these rules itself, but it does so after the process has
    started.  Checking here turns a subprocess failure into a message the caller
    can act on.
    """
    if not target_python:
        used = sorted(
            name for name, value in (
                ("target_os", target_os),
                ("target_arch", target_arch),
                ("target_libc", target_libc),
                ("target_platform", target_platform),
                ("target_implementation", target_implementation),
                ("target_abi", target_abi),
            ) if value
        )
        if used:
            raise ValueError(
                f"target_python is required when selecting artifacts. Got {', '.join(used)} without it."
            )
        return []

    if bool(target_os) != bool(target_arch):
        raise ValueError("target_os and target_arch must be provided together.")
    if target_libc and not target_os:
        raise ValueError("target_libc requires target_os and target_arch.")

    args = ["--target-python", target_python]
    for flag, value in (
        ("--target-os", target_os),
        ("--target-arch", target_arch),
        ("--target-libc", target_libc),
        ("--target-implementation", target_implementation),
    ):
        if value:
            args += [flag, value]

    # --target-platform and --target-abi are repeatable and take one value each
    for flag, value in (("--target-platform", target_platform), ("--target-abi", target_abi)):
        for item in _split_csv(value):
            args += [flag, item]

    return args


def _run_scan(
    target: str,
    *,
    report_name: str,
    profile: str | None = None,
    extra_args: list[str] | None = None,
) -> tuple[dict, str]:
    """Run rl-protect scan. Returns (parsed_report, report_id).

    `target` is passed verbatim to rl-protect — callers normalize as needed
    (PURL lists go through _normalize_purls; manifest paths are passed as-is).
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

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


def _get_effective_status(entry: dict) -> str:
    return (entry.get("override") or {}).get("to_status") or entry.get("status", "pass")


def _worst_label(analysis: dict) -> str:
    for g in analysis.get("policy", {}).get("governance", []):
        if g.get("status") == "blocked":
            return "Governance block"
    assessment = analysis.get("assessment", {})
    ws = _worst_status(assessment)
    repo = assessment.get("repository", {})
    if repo.get("status", "pass") != "pass":
        return repo.get("label", "")
    for k in _ASSESSMENT_PRIORITY:
        if assessment.get(k, {}).get("status") == ws:
            return assessment.get(k, {}).get("label", "")
    for v in analysis.get("policy", {}).get("violations", {}).values():
        if _get_effective_status(v) in ("fail", "warning"):
            return "Policy violation"
    return ""


def _format_result(report: dict, report_id: str) -> str:
    """Return a compact scan result: one row per package, summary counts, report_id."""
    report_analysis = report.get("analysis", {})
    report_data = report_analysis.get("report", {})

    packages = []
    n_reject = n_warn = 0
    for pkg in report_data.get("packages", []):
        pkg_analysis = pkg.get("analysis", {})
        rec = pkg_analysis.get("recommendation", "APPROVE")
        assessment = pkg_analysis.get("assessment", {})
        ws = _worst_status(assessment)
        # With artifact selection the purl carries a ?artifact=<file> qualifier.
        # Keep purl clean and report the artifact separately, so callers that
        # split the purl into name and version are unaffected.
        purl, _, qualifier = pkg.get("purl", "").partition("?")
        entry = {
            "purl": purl,
            "recommendation": rec,
            "worst_status": ws,
            "worst_label": _worst_label(pkg_analysis),
        }
        if qualifier:
            entry["artifact"] = (pkg.get("artifact") or {}).get("name", "")
        packages.append(entry)
        if rec == "REJECT":
            n_reject += 1
        elif ws in ("warning", "fail"):
            n_warn += 1

    total = len(packages)
    return json.dumps({
        "report_id": report_id,
        "metadata": {
            "timestamp": report_analysis.get("timestamp"),
            "duration": report_analysis.get("duration"),
            "profile": report_analysis.get("profile", {}).get("name"),
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
    target_python: str | None = None,
    target_platform: str | None = None,
    target_os: str | None = None,
    target_arch: str | None = None,
    target_libc: str | None = None,
    target_implementation: str | None = None,
    target_abi: str | None = None,
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
        and, when artifact selection was used, artifact (the selected file name)
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

      Add an "Artifact" column only if the packages carry an artifact field.

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

        The remaining arguments select a specific artifact for a target platform, so the
        scan assesses the file that would actually be installed. PyPI packages only.
        Omit them all to assess the package as a whole.

        target_python: Target Python version, e.g. "3.12" or "312". Required to enable
            artifact selection: the other target_* arguments do nothing without it.
        target_platform: Comma-separated platform tags (e.g. "manylinux_2_28_x86_64") or
            presets: linux-x86_64, linux-aarch64, linux-musl-x86_64, linux-musl-aarch64,
            macos-arm64, macos-x86_64, windows-x64, windows-x86, windows-arm64.
        target_os: Target OS: linux, macos, or windows. Optional ":version" as a macOS
            deployment-target floor, e.g. "macos:12.0". Must be given with target_arch.
            This is an alternative to target_platform, not an addition to it — supplying
            both selects the union of the two, which is usually wider than intended.
        target_arch: Target CPU architecture: x86_64, x86, or arm64. Must be given with target_os.
        target_libc: Target Linux libc: glibc, musl, or none. Optional ":version" as a
            floor, e.g. "glibc:2.34". Requires target_os and target_arch.
        target_implementation: Target Python interpreter: cp (default), pp, jy, ip, or py.
        target_abi: Comma-separated ABI tags, e.g. "cp312,abi3". Derived from target_python
            when omitted.
    """
    extra_args = ["--check-deps", check_deps] if check_deps else []
    extra_args += _target_args(
        target_python=target_python,
        target_os=target_os,
        target_arch=target_arch,
        target_libc=target_libc,
        target_platform=target_platform,
        target_implementation=target_implementation,
        target_abi=target_abi,
    )
    report, report_id = await asyncio.to_thread(
        _run_scan, _normalize_purls(purls),
        report_name=report_name, profile=profile, extra_args=extra_args,
    )
    return _format_result(report, report_id)


@mcp.tool()
async def rl_protect_scan_manifest(
    manifest_path: str,
    report_name: str,
    profile: str | None = None,
    check_deps: str | None = None,
    target_python: str | None = None,
    target_platform: str | None = None,
    target_os: str | None = None,
    target_arch: str | None = None,
    target_libc: str | None = None,
    target_implementation: str | None = None,
    target_abi: str | None = None,
) -> str:
    """Scan a manifest or lock file for supply chain risk using ReversingLabs Spectra Assure.

    Use this tool to scan project dependency files that are accessible inside the
    container. Supported files:
      Node.js  package.json, package-lock.json, pnpm-lock.yaml, yarn.lock (Classic)
      Python   requirements.txt, pyproject.toml, setup.cfg, poetry.lock, uv.lock
      Ruby     Gemfile, gemspec, Gemfile.lock
    Prefer the lock file when the project has one — it pins exact versions.

    IMPORTANT — Volume mount required: The MCP server runs inside a Docker container
    and cannot access host files directly. The user must mount their project directory
    when starting the container:

      docker run --rm -i -e RL_TOKEN=... -v /path/to/project:/project:ro rl-mcp-community

    Then pass container-relative paths like "/project/package.json".

    Returns the same compact JSON structure as rl_protect_scan — use
    rl_protect_summarize(report_id) to drill into any package that needs investigation:
      report_id: unique identifier for querying this report later
      metadata: {timestamp, duration, profile}
      summary: {reject, warn, pass, total}
      packages[]: each with {purl, recommendation (APPROVE/REJECT),
        worst_status (pass/warning/fail), worst_label (human-readable worst check)}
        and, when artifact selection was used, artifact (the selected file name)
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

      Add an "Artifact" column only if the packages carry an artifact field.

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

        The remaining arguments select a specific artifact for a target platform, so the
        scan assesses the file that would actually be installed. PyPI packages only, so
        they have no effect on a package.json or Gemfile scan. Use them when you know the
        deployment target, for example from a Dockerfile base image or a CI matrix.
        Omit them all to assess each package as a whole.

        target_python: Target Python version, e.g. "3.12" or "312". Required to enable
            artifact selection: the other target_* arguments do nothing without it.
        target_platform: Comma-separated platform tags (e.g. "manylinux_2_28_x86_64") or
            presets: linux-x86_64, linux-aarch64, linux-musl-x86_64, linux-musl-aarch64,
            macos-arm64, macos-x86_64, windows-x64, windows-x86, windows-arm64.
        target_os: Target OS: linux, macos, or windows. Optional ":version" as a macOS
            deployment-target floor, e.g. "macos:12.0". Must be given with target_arch.
            This is an alternative to target_platform, not an addition to it — supplying
            both selects the union of the two, which is usually wider than intended.
        target_arch: Target CPU architecture: x86_64, x86, or arm64. Must be given with target_os.
        target_libc: Target Linux libc: glibc, musl, or none. Optional ":version" as a
            floor, e.g. "glibc:2.34". Requires target_os and target_arch.
        target_implementation: Target Python interpreter: cp (default), pp, jy, ip, or py.
        target_abi: Comma-separated ABI tags, e.g. "cp312,abi3". Derived from target_python
            when omitted.
    """
    extra_args = ["--check-deps", check_deps] if check_deps else []
    extra_args += _target_args(
        target_python=target_python,
        target_os=target_os,
        target_arch=target_arch,
        target_libc=target_libc,
        target_platform=target_platform,
        target_implementation=target_implementation,
        target_abi=target_abi,
    )
    report, report_id = await asyncio.to_thread(
        _run_scan, manifest_path, report_name=report_name, profile=profile, extra_args=extra_args,
    )
    return _format_result(report, report_id)
