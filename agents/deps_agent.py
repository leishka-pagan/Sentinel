"""
sentinel/agents/deps_agent.py

Dependency Agent — CVE scanning on Python requirements files.
Uses pip-audit against the OSV vulnerability database.

SCOPE: CODE mode only.
ACTIONS: dependency_scan, file_read
NEVER: installs packages, makes changes, touches network beyond OSV API
"""

import subprocess
import json
from pathlib import Path

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity,
)


REQUIREMENTS_FILES = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements/base.txt",
    "requirements/prod.txt",
    "pyproject.toml",
    "setup.py",
    "Pipfile",
]


def run_deps_agent(session: ScanSession, source_path: str) -> list[Finding]:
    """
    Scan for vulnerable dependencies in the provided source directory.
    Finds requirements files and runs pip-audit on each.
    """
    validate_action(
        agent=AgentName.DEPS,
        action="dependency_scan",
        target=source_path,
        session=session,
        reason=f"Dependency CVE scan on {source_path}",
    )

    base = Path(source_path)
    all_findings: list[Finding] = []

    # Find all requirements files
    req_files = _find_requirements_files(base)

    if not req_files:
        print(f"[DEPS] No requirements files found in {source_path}")
        return []

    for req_file in req_files:
        print(f"[DEPS] Scanning {req_file}")
        findings = _run_pip_audit(str(req_file), session)
        all_findings.extend(findings)

    print(f"[DEPS] {len(all_findings)} vulnerable dependencies found")
    return all_findings


# ── pip-audit ─────────────────────────────────────────────────────────────────

def _run_pip_audit(req_file: str, session: ScanSession) -> list[Finding]:
    """Run pip-audit on a single requirements file."""
    try:
        result = subprocess.run(
            [
                "pip-audit",
                "-r", req_file,
                "-f", "json",
                "--no-deps",   # don't install — just audit what's listed
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        # pip-audit exits 1 when vulnerabilities found — normal
        if result.returncode not in (0, 1):
            print(f"[DEPS/pip-audit] Unexpected exit code {result.returncode}")
            print(f"[DEPS/pip-audit] stderr: {result.stderr[:500]}")
            return []

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        findings = []

        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                findings.append(_vuln_to_finding(dep, vuln, req_file))

        return findings

    except subprocess.TimeoutExpired:
        print(f"[DEPS/pip-audit] Timed out scanning {req_file}")
        return []
    except FileNotFoundError:
        print("[DEPS/pip-audit] pip-audit not installed. Run: pip install pip-audit")
        return []
    except json.JSONDecodeError as e:
        print(f"[DEPS/pip-audit] Failed to parse output: {e}")
        return []


def _vuln_to_finding(dep: dict, vuln: dict, req_file: str) -> Finding:
    """Convert a pip-audit vulnerability entry to a Finding."""
    package = dep.get("name", "unknown")
    version = dep.get("version", "unknown")
    vuln_id = vuln.get("id", "UNKNOWN")
    aliases = vuln.get("aliases", [])
    description = vuln.get("description", "No description available.")
    fix_versions = vuln.get("fix_versions", [])

    # Extract CVE from aliases if present
    cve = next((a for a in aliases if a.startswith("CVE-")), None)

    # Estimate severity from CVSS if available (pip-audit doesn't always include it)
    severity = _estimate_severity(vuln_id, description)

    fix_str = (
        f"Upgrade to version {', '.join(fix_versions)}."
        if fix_versions
        else "No fix version available — consider replacing this dependency."
    )

    return Finding(
        agent=AgentName.DEPS,
        title=f"Vulnerable Dependency: {package}=={version} ({vuln_id})",
        description=(
            f"Package '{package}' version {version} has a known vulnerability: {description}"
        ),
        severity=severity,
        file_path=req_file,
        cve_id=cve or vuln_id,
        mitre_tactic="Initial Access",
        mitre_technique="T1195.001 — Compromise Software Dependencies",
        remediation=(
            f"{fix_str} "
            f"Review the vulnerability advisory at https://osv.dev/vulnerability/{vuln_id}. "
            "After upgrading, re-run this scan to confirm the vulnerability is resolved."
        ),
        raw_output=json.dumps({"dep": dep, "vuln": vuln}),
    )


def _estimate_severity(vuln_id: str, description: str) -> Severity:
    """
    Rough severity estimation when CVSS is not available.
    Phase 2 will pull actual CVSS scores from OSV API.
    """
    desc_lower = description.lower()
    critical_keywords = ["remote code execution", "rce", "arbitrary code", "authentication bypass"]
    high_keywords     = ["sql injection", "privilege escalation", "xxe", "ssrf", "deserialization"]
    medium_keywords   = ["xss", "csrf", "open redirect", "path traversal", "denial of service"]

    for kw in critical_keywords:
        if kw in desc_lower:
            return Severity.CRITICAL
    for kw in high_keywords:
        if kw in desc_lower:
            return Severity.HIGH
    for kw in medium_keywords:
        if kw in desc_lower:
            return Severity.MEDIUM
    return Severity.LOW


def _find_requirements_files(base: Path) -> list[Path]:
    """
    Find all requirements files in the source directory.
    Checks known filenames at root and one level deep.
    """
    found = []
    for name in REQUIREMENTS_FILES:
        # Root level
        p = base / name
        if p.exists():
            found.append(p)
        # One level deep
        for subdir in base.iterdir():
            if subdir.is_dir():
                p2 = subdir / name
                if p2.exists():
                    found.append(p2)
    return list(set(found))
