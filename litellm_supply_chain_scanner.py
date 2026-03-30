#!/usr/bin/env python3
"""
litellm Supply Chain Attack Scanner
=====================================
Scans a local repository or directory to detect whether it is vulnerable to
the litellm PyPI supply chain attack (March 24, 2026).

Affected versions: litellm 1.82.7 and 1.82.8

Usage:
  python3 litellm_supply_chain_scanner.py /path/to/repo
  python3 litellm_supply_chain_scanner.py .
  python3 litellm_supply_chain_scanner.py --help

Exit codes:
  0 — No vulnerability detected
  1 — Vulnerability / IOC detected
  2 — Scanner error

References:
  https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
  https://blog.pluto.security/p/analyzing-the-supply-chain-attack
  https://github.com/BerriAI/litellm/issues/24512
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AFFECTED_VERSIONS = {"1.82.7", "1.82.8"}
SAFE_VERSION_MIN = "1.82.9"

# Regex to match version strings like 1.82.7 or 1.82.8
AFFECTED_VERSION_RE = re.compile(r"1\.82\.[78]")

# Match litellm pinned to an affected version in requirements-style files
# Handles: litellm==1.82.7  litellm==1.82.8  litellm[proxy]==1.82.7  etc.
REQUIREMENTS_RE = re.compile(
    r"(?i)litellm(\[[\w,\s]+\])?\s*==\s*(1\.82\.[78])"
)

# Match version ranges that INCLUDE the affected versions
# e.g. litellm>=1.82.0,<1.82.9  or  litellm>=1.82.7
REQUIREMENTS_RANGE_RE = re.compile(
    r"(?i)litellm(\[[\w,\s]+\])?\s*(>=|~=)\s*(1\.82\.[0-8](?!\d))"
)

# For pyproject.toml / setup.cfg / setup.py
PYPROJECT_RE = re.compile(
    r"(?i)[\"']?litellm(\[[\w,\s]+\])?[\"']?\s*[=:]\s*[\"']?\s*(==)?\s*(1\.82\.[78])"
)

# Poetry lock — version line after litellm package block
POETRY_LOCK_NAME_RE = re.compile(r'^name\s*=\s*"litellm"', re.IGNORECASE)
POETRY_LOCK_VER_RE  = re.compile(r'^version\s*=\s*"([^"]+)"')

# uv.lock format
UV_LOCK_NAME_RE = re.compile(r'^name\s*=\s*"litellm"', re.IGNORECASE)
UV_LOCK_VER_RE  = re.compile(r'^version\s*=\s*"([^"]+)"')

# Pipfile.lock — JSON; litellm key under default/develop
# environment.yml conda pinning
CONDA_RE = re.compile(r"(?i)-\s*litellm\s*==\s*(1\.82\.[78])")

# Docker — pip install litellm==<ver> or litellm[proxy]==<ver>
DOCKER_RE = re.compile(
    r"(?i)pip\s+install\s+[^\n]*litellm(\[[\w,]+\])?\s*==\s*(1\.82\.[78])"
)

# GitHub Actions / CI — install commands
CI_RE = re.compile(
    r"(?i)pip\s+install\s+[^\n]*litellm(\[[\w,]+\])?\s*==\s*(1\.82\.[78])"
)

# Python source direct import (flag as informational, not necessarily vulnerable)
PYTHON_IMPORT_RE = re.compile(r"^\s*(import litellm|from litellm\s+import)", re.MULTILINE)

# IOC: malicious .pth filename
MALICIOUS_PTH_NAME = "litellm_init.pth"

# IOC: sysmon backdoor path patterns
SYSMON_PATTERNS = [
    re.compile(r"\.config[/\\]sysmon[/\\]sysmon\.py"),
    re.compile(r"\.config[/\\]systemd[/\\]user[/\\]sysmon\.service"),
    re.compile(r"models\.litellm\.cloud"),
]

# Directories to skip
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".tox", "node_modules", ".venv", "venv", "env", ".env",
    "dist", "build", ".eggs", "*.egg-info",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str          # CRITICAL / HIGH / INFO
    file: str
    line: int              # 0 if N/A
    detail: str
    remediation: str = ""

@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    scanned_files: int = 0

    def add(self, f: Finding):
        self.findings.append(f)

    @property
    def vulnerable(self) -> bool:
        return any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_affected_version(ver: str) -> bool:
    return ver.strip() in AFFECTED_VERSIONS


def walk_repo(root: Path):
    """Yield all files in repo, skipping irrelevant directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune directories in-place
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.endswith(".egg-info")
        ]
        for fname in filenames:
            yield Path(dirpath) / fname


def rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def read_lines(path: Path) -> Optional[List[str]]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Individual checkers
# ---------------------------------------------------------------------------

def check_requirements_file(root: Path, path: Path, result: ScanResult):
    """requirements.txt, constraints.txt, pip freeze files."""
    lines = read_lines(path)
    if lines is None:
        return
    result.scanned_files += 1
    for i, line in enumerate(lines, 1):
        line_stripped = line.strip()
        if line_stripped.startswith("#") or not line_stripped:
            continue

        m = REQUIREMENTS_RE.search(line_stripped)
        if m:
            ver = m.group(2)
            result.add(Finding(
                severity="CRITICAL",
                file=rel(root, path),
                line=i,
                detail=f"litellm pinned to COMPROMISED version {ver}: `{line_stripped}`",
                remediation=f"Upgrade to litellm>={SAFE_VERSION_MIN} — remove or replace this line."
            ))
            continue

        # Loose range that could resolve to an affected version
        m2 = REQUIREMENTS_RANGE_RE.search(line_stripped)
        if m2:
            result.add(Finding(
                severity="HIGH",
                file=rel(root, path),
                line=i,
                detail=f"litellm version range MAY resolve to compromised 1.82.7/1.82.8: `{line_stripped}`",
                remediation=f"Pin to litellm>={SAFE_VERSION_MIN} or add a lower-bound exclusion."
            ))


def check_poetry_lock(root: Path, path: Path, result: ScanResult):
    lines = read_lines(path)
    if lines is None:
        return
    result.scanned_files += 1
    in_litellm_block = False
    for i, line in enumerate(lines, 1):
        if POETRY_LOCK_NAME_RE.match(line.strip()):
            in_litellm_block = True
            continue
        if in_litellm_block:
            m = POETRY_LOCK_VER_RE.match(line.strip())
            if m:
                ver = m.group(1)
                if is_affected_version(ver):
                    result.add(Finding(
                        severity="CRITICAL",
                        file=rel(root, path),
                        line=i,
                        detail=f"poetry.lock pins litellm to COMPROMISED version {ver}",
                        remediation=f"Run `poetry update litellm` and ensure litellm>={SAFE_VERSION_MIN}."
                    ))
                in_litellm_block = False
            elif line.strip().startswith("[["):
                in_litellm_block = False


def check_uv_lock(root: Path, path: Path, result: ScanResult):
    lines = read_lines(path)
    if lines is None:
        return
    result.scanned_files += 1
    in_litellm_block = False
    for i, line in enumerate(lines, 1):
        if UV_LOCK_NAME_RE.match(line.strip()):
            in_litellm_block = True
            continue
        if in_litellm_block:
            m = UV_LOCK_VER_RE.match(line.strip())
            if m:
                ver = m.group(1)
                if is_affected_version(ver):
                    result.add(Finding(
                        severity="CRITICAL",
                        file=rel(root, path),
                        line=i,
                        detail=f"uv.lock pins litellm to COMPROMISED version {ver}",
                        remediation=f"Run `uv lock --upgrade-package litellm` and ensure litellm>={SAFE_VERSION_MIN}."
                    ))
                in_litellm_block = False
            elif line.strip().startswith("[["):
                in_litellm_block = False


def check_pipfile_lock(root: Path, path: Path, result: ScanResult):
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return
    result.scanned_files += 1
    for section in ("default", "develop"):
        pkgs = data.get(section, {})
        if "litellm" in pkgs:
            ver_spec = pkgs["litellm"].get("version", "")
            # Remove == prefix
            ver = ver_spec.lstrip("=").strip()
            if is_affected_version(ver):
                result.add(Finding(
                    severity="CRITICAL",
                    file=rel(root, path),
                    line=0,
                    detail=f"Pipfile.lock [{section}] pins litellm to COMPROMISED version {ver}",
                    remediation=f"Run `pipenv update litellm` and ensure litellm>={SAFE_VERSION_MIN}."
                ))


def check_pyproject_toml(root: Path, path: Path, result: ScanResult):
    lines = read_lines(path)
    if lines is None:
        return
    result.scanned_files += 1
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if "litellm" not in stripped.lower():
            continue
        # Look for litellm = "1.82.7" or litellm = "==1.82.7" or litellm = "^1.82.7"
        m = re.search(
            r'(?i)["\']?litellm(\[[\w,\s]+\])?["\']?\s*[=:]\s*["\']([^"\']+)["\']',
            stripped
        )
        if m:
            ver_spec = m.group(2).strip()
            # Check exact match
            clean_ver = ver_spec.lstrip("=^~>< ").strip()
            if is_affected_version(clean_ver):
                result.add(Finding(
                    severity="CRITICAL",
                    file=rel(root, path),
                    line=i,
                    detail=f"pyproject.toml pins litellm to COMPROMISED version: `{stripped}`",
                    remediation=f"Update litellm dependency to >={SAFE_VERSION_MIN}."
                ))
            elif AFFECTED_VERSION_RE.search(ver_spec):
                result.add(Finding(
                    severity="HIGH",
                    file=rel(root, path),
                    line=i,
                    detail=f"pyproject.toml version spec may include compromised versions: `{stripped}`",
                    remediation=f"Constrain litellm to >={SAFE_VERSION_MIN}."
                ))


def check_setup_file(root: Path, path: Path, result: ScanResult):
    """setup.py or setup.cfg"""
    lines = read_lines(path)
    if lines is None:
        return
    result.scanned_files += 1
    for i, line in enumerate(lines, 1):
        if "litellm" not in line.lower():
            continue
        m = REQUIREMENTS_RE.search(line)
        if m:
            ver = m.group(2)
            result.add(Finding(
                severity="CRITICAL",
                file=rel(root, path),
                line=i,
                detail=f"setup file pins litellm to COMPROMISED version {ver}: `{line.strip()}`",
                remediation=f"Update the install_requires entry to litellm>={SAFE_VERSION_MIN}."
            ))


def check_conda_env(root: Path, path: Path, result: ScanResult):
    lines = read_lines(path)
    if lines is None:
        return
    result.scanned_files += 1
    for i, line in enumerate(lines, 1):
        m = CONDA_RE.search(line)
        if m:
            ver = m.group(1)
            result.add(Finding(
                severity="CRITICAL",
                file=rel(root, path),
                line=i,
                detail=f"Conda environment pins litellm to COMPROMISED version {ver}: `{line.strip()}`",
                remediation=f"Update to litellm=={SAFE_VERSION_MIN} or higher in your conda environment."
            ))


def check_dockerfile(root: Path, path: Path, result: ScanResult):
    lines = read_lines(path)
    if lines is None:
        return
    result.scanned_files += 1
    for i, line in enumerate(lines, 1):
        m = DOCKER_RE.search(line)
        if m:
            ver = m.group(2)
            result.add(Finding(
                severity="CRITICAL",
                file=rel(root, path),
                line=i,
                detail=f"Dockerfile installs litellm COMPROMISED version {ver}: `{line.strip()}`",
                remediation=f"Change to `pip install litellm>={SAFE_VERSION_MIN}` in your Dockerfile."
            ))


def check_ci_workflow(root: Path, path: Path, result: ScanResult):
    lines = read_lines(path)
    if lines is None:
        return
    result.scanned_files += 1
    for i, line in enumerate(lines, 1):
        m = CI_RE.search(line)
        if m:
            ver = m.group(2)
            result.add(Finding(
                severity="CRITICAL",
                file=rel(root, path),
                line=i,
                detail=f"CI workflow installs litellm COMPROMISED version {ver}: `{line.strip()}`",
                remediation=f"Update the install step to use litellm>={SAFE_VERSION_MIN}."
            ))


def check_python_source(root: Path, path: Path, result: ScanResult):
    """Flag Python files that import litellm as informational — they may be affected at runtime."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    result.scanned_files += 1
    if PYTHON_IMPORT_RE.search(content):
        # Only add INFO finding — the actual risk depends on what version is installed
        result.add(Finding(
            severity="INFO",
            file=rel(root, path),
            line=0,
            detail="File imports litellm — if a compromised version is installed, this file will load malicious code",
            remediation="Ensure litellm installed in this environment is >= 1.82.9."
        ))


def check_ioc_pth_file(root: Path, path: Path, result: ScanResult):
    """Detect the actual malicious .pth artifact if somehow committed to the repo."""
    result.scanned_files += 1
    result.add(Finding(
        severity="CRITICAL",
        file=rel(root, path),
        line=0,
        detail=f"MALICIOUS FILE FOUND: `{MALICIOUS_PTH_NAME}` — this is the auto-execute backdoor dropper from litellm 1.82.8",
        remediation="Delete this file immediately. Rotate ALL credentials on this machine."
    ))


def check_ioc_patterns_in_file(root: Path, path: Path, result: ScanResult):
    """Search any file for known IOC strings (sysmon paths, exfil domain)."""
    # Avoid flagging this scanner or known detection tools on IOC strings they contain
    _SCANNER_NAMES = {"litellm_supply_chain_scanner.py", "detect.sh", "check_litellm_compromise.sh"}
    if path.name in _SCANNER_NAMES:
        return
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    result.scanned_files += 1
    for pat in SYSMON_PATTERNS:
        m = pat.search(content)
        if m:
            # Find line number
            line_no = content[: m.start()].count("\n") + 1
            result.add(Finding(
                severity="HIGH",
                file=rel(root, path),
                line=line_no,
                detail=f"IOC string detected: `{m.group()}` — matches known litellm malware artifact",
                remediation="Investigate this file. If not intentional, treat machine as compromised."
            ))

# ---------------------------------------------------------------------------
# File routing
# ---------------------------------------------------------------------------

REQUIREMENTS_NAMES = re.compile(
    r"(?i)(requirements|constraints)([\w\-.]*)\.txt$"
    r"|(frozen-requirements|pip-freeze)\.txt$"
    r"|pip[\-_]freeze\.txt$",
    re.IGNORECASE
)

DOCKERFILE_RE_NAME = re.compile(r"(?i)^Dockerfile(\.[\w]+)?$")


def route_file(root: Path, path: Path, result: ScanResult):
    name = path.name
    suffix = path.suffix.lower()

    # Hard IOC: malicious .pth file itself
    if name == MALICIOUS_PTH_NAME:
        check_ioc_pth_file(root, path, result)
        return

    # Requirements / pip freeze files
    if REQUIREMENTS_NAMES.match(name):
        check_requirements_file(root, path, result)
        check_ioc_patterns_in_file(root, path, result)
        return

    if name == "poetry.lock":
        check_poetry_lock(root, path, result)
        return

    if name == "uv.lock":
        check_uv_lock(root, path, result)
        return

    if name == "Pipfile.lock":
        check_pipfile_lock(root, path, result)
        return

    if name in ("pdm.lock",):
        # pdm.lock is similar to uv.lock format
        check_uv_lock(root, path, result)
        return

    if name in ("pyproject.toml",):
        check_pyproject_toml(root, path, result)
        return

    if name in ("setup.py", "setup.cfg"):
        check_setup_file(root, path, result)
        return

    if name in ("environment.yml", "environment.yaml", "conda-lock.yml"):
        check_conda_env(root, path, result)
        return

    if DOCKERFILE_RE_NAME.match(name) or name == "docker-compose.yml" or name == "docker-compose.yaml":
        check_dockerfile(root, path, result)
        return

    # GitHub Actions / CI
    if ".github" in str(path) and suffix in (".yml", ".yaml"):
        check_ci_workflow(root, path, result)
        return

    if "ci" in name.lower() and suffix in (".yml", ".yaml"):
        check_ci_workflow(root, path, result)
        return

    # Python source files
    if suffix == ".py":
        check_python_source(root, path, result)
        # Also scan for IOC strings in Python files
        check_ioc_patterns_in_file(root, path, result)
        return

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "INFO": 2}
SEVERITY_COLOR = {
    "CRITICAL": "\033[0;31m",   # red
    "HIGH":     "\033[1;33m",   # yellow
    "INFO":     "\033[0;34m",   # blue
}
RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[0;32m"
RED   = "\033[0;31m"


def colorize(text: str, color: str) -> str:
    if sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return text


def print_report(result: ScanResult, root: Path, no_color: bool = False):
    def c(text, color):
        return text if no_color else colorize(text, color)

    print()
    print(c("=" * 65, BOLD))
    print(c("  litellm Supply Chain Attack Scanner", BOLD))
    print(c("  Affected versions: 1.82.7, 1.82.8 (March 24, 2026)", BOLD))
    print(c("=" * 65, BOLD))
    print(f"  Repo scanned : {root.resolve()}")
    print(f"  Files scanned: {result.scanned_files}")
    print()

    if not result.findings:
        print(c("  [CLEAN] No indicators of compromise found.", GREEN))
        print()
        print("  If you have never installed litellm 1.82.7 or 1.82.8 in")
        print("  any environment that runs this code, you are not affected.")
        print(c("=" * 65, BOLD))
        return

    # Sort: CRITICAL first, then HIGH, then INFO
    sorted_findings = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    critical = [f for f in sorted_findings if f.severity == "CRITICAL"]
    high     = [f for f in sorted_findings if f.severity == "HIGH"]
    info     = [f for f in sorted_findings if f.severity == "INFO"]

    if critical or high:
        print(c(f"  [!] VULNERABILITY DETECTED", RED))
    print(f"  Critical : {len(critical)}")
    print(f"  High     : {len(high)}")
    print(f"  Info     : {len(info)}")
    print()

    for f in sorted_findings:
        color = SEVERITY_COLOR.get(f.severity, "")
        label = c(f"[{f.severity}]", color)
        loc   = f"{f.file}" + (f":{f.line}" if f.line else "")
        print(f"  {label} {loc}")
        print(f"         {f.detail}")
        if f.remediation:
            print(f"         → {f.remediation}")
        print()

    print(c("=" * 65, BOLD))

    if result.vulnerable:
        print(c("  RESULT: This repository is VULNERABLE or COMPROMISED", RED))
        print()
        print("  Immediate actions:")
        print("    1. Do NOT run this code until litellm is upgraded.")
        print(f"   2. Upgrade: pip install --upgrade 'litellm>={SAFE_VERSION_MIN}'")
        print("    3. Update ALL lock files (poetry.lock, uv.lock, etc.).")
        print("    4. If the compromised version was ever INSTALLED and run:")
        print("       a. Rotate all secrets (AWS, GCP, Azure, SSH, API keys)")
        print("       b. Check ~/.config/sysmon/ for persistence backdoor")
        print("       c. Check kubectl kube-system for node-setup-* pods")
        print("       d. Check outbound DNS for models.litellm.cloud")
        print()
        print("  Reference: https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/")
    else:
        print(c("  RESULT: No critical/high vulnerability found (INFO findings only).", GREEN))
        print()
        print("  INFO findings indicate litellm usage — ensure your deployed")
        print(f"  environment installs litellm>={SAFE_VERSION_MIN}.")

    print(c("=" * 65, BOLD))
    print()


def print_json_report(result: ScanResult, root: Path):
    data = {
        "repo": str(root.resolve()),
        "files_scanned": result.scanned_files,
        "vulnerable": result.vulnerable,
        "summary": {
            "critical": sum(1 for f in result.findings if f.severity == "CRITICAL"),
            "high":     sum(1 for f in result.findings if f.severity == "HIGH"),
            "info":     sum(1 for f in result.findings if f.severity == "INFO"),
        },
        "findings": [
            {
                "severity":    f.severity,
                "file":        f.file,
                "line":        f.line,
                "detail":      f.detail,
                "remediation": f.remediation,
            }
            for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99))
        ],
        "affected_versions": list(AFFECTED_VERSIONS),
        "safe_version_minimum": SAFE_VERSION_MIN,
        "reference": "https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/",
    }
    print(json.dumps(data, indent=2))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan a repository for the litellm supply chain attack (1.82.7 / 1.82.8)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "repo",
        nargs="?",
        default=".",
        help="Path to repository or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format (useful for CI pipelines)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress INFO findings; only show CRITICAL and HIGH",
    )
    args = parser.parse_args()

    root = Path(args.repo).resolve()
    if not root.exists():
        print(f"ERROR: Path does not exist: {root}", file=sys.stderr)
        sys.exit(2)
    if not root.is_dir():
        print(f"ERROR: Path is not a directory: {root}", file=sys.stderr)
        sys.exit(2)

    result = ScanResult()

    for path in walk_repo(root):
        try:
            route_file(root, path, result)
        except Exception as e:
            # Never crash on a single file
            print(f"[WARN] Could not process {path}: {e}", file=sys.stderr)

    # Apply quiet filter
    if args.quiet:
        result.findings = [f for f in result.findings if f.severity != "INFO"]

    if args.json:
        print_json_report(result, root)
    else:
        print_report(result, root, no_color=args.no_color)

    sys.exit(1 if result.vulnerable else 0)


if __name__ == "__main__":
    main()