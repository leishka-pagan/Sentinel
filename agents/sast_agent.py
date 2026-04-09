"""
sentinel/agents/sast_agent.py

SAST Agent — Static Application Security Testing.
Runs Bandit on Python source code, parses output,
and returns structured Finding objects.

SCOPE: CODE mode only.
ACTIONS: sast_scan, file_read
NEVER: executes code, touches network, writes files
"""

import subprocess
import json
import os
from pathlib import Path

from sentinel.core import (
    validate_action, AgentName, ScanSession, Finding, Severity, ScanMode,
    ModeViolation,
)


def run_sast_agent(session: ScanSession, source_path: str) -> list[Finding]:
    """
    Run SAST analysis on the provided source path.
    Returns a list of Finding objects.
    """
    # Validate before touching anything
    validate_action(
        agent=AgentName.SAST,
        action="sast_scan",
        target=source_path,
        session=session,
        reason=f"SAST scan requested on {source_path}",
    )

    if session.mode == ScanMode.PASSIVE:
        raise ModeViolation("SAST agent cannot run in PASSIVE mode.")

    path = Path(source_path)
    if not path.exists():
        print(f"[SAST] Source path does not exist: {source_path}")
        return []

    findings: list[Finding] = []

    # Run Bandit
    bandit_findings = _run_bandit(source_path, session)
    findings.extend(bandit_findings)

    # Run TruffleHog (secrets scan)
    secrets_findings = _run_secrets_scan(source_path, session)
    findings.extend(secrets_findings)

    print(f"[SAST] {len(findings)} findings from {source_path}")
    return findings


# ── Bandit ────────────────────────────────────────────────────────────────────

def _run_bandit(source_path: str, session: ScanSession) -> list[Finding]:
    """Run Bandit static analysis and parse JSON output."""
    try:
        result = subprocess.run(
            [
                "bandit",
                "-r",          # recursive
                "-f", "json",  # JSON output
                "-ll",         # low severity and above
                source_path,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        # Bandit exits 1 when it finds issues — that's normal
        if result.returncode not in (0, 1):
            print(f"[SAST/Bandit] Unexpected exit code: {result.returncode}")
            print(f"[SAST/Bandit] stderr: {result.stderr[:500]}")
            return []

        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        return [_bandit_result_to_finding(r, session) for r in data.get("results", [])]

    except subprocess.TimeoutExpired:
        print("[SAST/Bandit] Scan timed out after 120s")
        return []
    except FileNotFoundError:
        print("[SAST/Bandit] Bandit not installed. Run: pip install bandit")
        return []
    except json.JSONDecodeError as e:
        print(f"[SAST/Bandit] Failed to parse JSON output: {e}")
        return []


def _bandit_result_to_finding(result: dict, session: ScanSession) -> Finding:
    """Convert a Bandit result dict to a Finding."""
    severity_map = {
        "HIGH":   Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW":    Severity.LOW,
    }
    severity = severity_map.get(result.get("issue_severity", "LOW"), Severity.LOW)

    return Finding(
        agent=AgentName.SAST,
        title=result.get("test_name", "Unknown Issue"),
        description=result.get("issue_text", ""),
        severity=severity,
        file_path=result.get("filename"),
        line_number=result.get("line_number"),
        cve_id=None,  # Bandit doesn't map to CVEs
        mitre_tactic=_bandit_to_mitre_tactic(result.get("test_id", "")),
        remediation=_generate_remediation(result),
        raw_output=json.dumps(result),
    )


def _bandit_to_mitre_tactic(test_id: str) -> str:
    """
    Map Bandit test IDs to MITRE ATT&CK tactics (rough mapping).
    Phase 2 will have a full mapping table.
    """
    tactic_map = {
        "B101": "Defense Evasion",          # assert used
        "B102": "Execution",                 # exec used
        "B103": "Defense Evasion",          # setting permissions
        "B104": "Command and Control",       # hardcoded bind all interfaces
        "B105": "Credential Access",         # hardcoded password string
        "B106": "Credential Access",         # hardcoded password function arg
        "B107": "Credential Access",         # hardcoded password default
        "B108": "Discovery",                 # probable insecure temp file
        "B110": "Defense Evasion",          # try/except pass
        "B201": "Initial Access",            # flask debug mode
        "B301": "Execution",                 # pickle use
        "B302": "Execution",                 # marshal use
        "B303": "Credential Access",         # MD2/MD4/MD5 use
        "B304": "Credential Access",         # ciphers with no IV
        "B305": "Credential Access",         # cipher block chaining
        "B306": "Execution",                 # mktemp use
        "B307": "Execution",                 # eval use
        "B308": "Execution",                 # mark_safe use
        "B310": "Initial Access",            # urllib urlopen
        "B311": "Defense Evasion",          # random not for crypto
        "B312": "Command and Control",       # telnetlib use
        "B314": "Initial Access",            # xml ET parse
        "B320": "Initial Access",            # xml.etree
        "B321": "Command and Control",       # FTP
        "B322": "Execution",                 # input() py2
        "B323": "Defense Evasion",          # unverified context
        "B324": "Credential Access",         # hashlib
        "B325": "Defense Evasion",          # tempnam
        "B401": "Exfiltration",              # import telnetlib
        "B402": "Exfiltration",              # import ftplib
        "B403": "Execution",                 # import pickle
        "B404": "Execution",                 # import subprocess
        "B405": "Execution",                 # import xml.etree
        "B501": "Defense Evasion",          # request with verify=False
        "B502": "Defense Evasion",          # ssl with no version
        "B503": "Defense Evasion",          # ssl with bad defaults
        "B504": "Defense Evasion",          # ssl with no cert requirements
        "B505": "Credential Access",         # weak crypto key
        "B506": "Execution",                 # yaml load
        "B507": "Defense Evasion",          # ssh no host key verify
        "B601": "Execution",                 # paramiko exec command
        "B602": "Execution",                 # subprocess with shell=True
        "B603": "Execution",                 # subprocess without shell=True
        "B604": "Execution",                 # function call with shell=True
        "B605": "Execution",                 # start process with shell
        "B606": "Execution",                 # start process no shell
        "B607": "Execution",                 # start process with partial path
        "B608": "Initial Access",            # hardcoded SQL
        "B609": "Execution",                 # wildcard injection
        "B610": "Initial Access",            # django SQL extra
        "B611": "Initial Access",            # django RawSQL
        "B701": "Defense Evasion",          # jinja2 autoescape
        "B702": "Initial Access",            # mako templates
        "B703": "Initial Access",            # django mark_safe
    }
    return tactic_map.get(test_id, "Unknown")


def _generate_remediation(result: dict) -> str:
    """Generate a basic remediation hint from Bandit result metadata."""
    issue = result.get("issue_text", "")
    test_id = result.get("test_id", "")
    cwe = result.get("issue_cwe", {})
    cwe_id = cwe.get("id", "") if isinstance(cwe, dict) else ""

    base = f"Address the {result.get('test_name', 'identified issue')}. "
    if cwe_id:
        base += f"See CWE-{cwe_id} for guidance. "
    base += "Review Bandit documentation and apply the recommended fix. "
    base += "Do not suppress this warning without understanding the root cause."
    return base


# ── Secrets Scan ─────────────────────────────────────────────────────────────

def _run_secrets_scan(source_path: str, session: ScanSession) -> list[Finding]:
    """
    Run TruffleHog on local filesystem to detect hardcoded secrets.
    Uses filesystem mode (no network, no git history required).
    """
    try:
        validate_action(
            agent=AgentName.SAST,
            action="secrets_scan",
            target=source_path,
            session=session,
            reason="Secrets scan on local source",
        )

        result = subprocess.run(
            [
                "trufflehog",
                "filesystem",
                source_path,
                "--json",
                "--no-update",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        findings = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                hit = json.loads(line)
                findings.append(_trufflehog_to_finding(hit))
            except json.JSONDecodeError:
                continue

        return findings

    except subprocess.TimeoutExpired:
        print("[SAST/TruffleHog] Scan timed out")
        return []
    except FileNotFoundError:
        print("[SAST/TruffleHog] TruffleHog not installed. Run: pip install truffleHog3")
        return []


def _trufflehog_to_finding(hit: dict) -> Finding:
    """Convert a TruffleHog JSON hit to a Finding."""
    detector = hit.get("DetectorName", "Unknown Secret Type")
    file_path = hit.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", None)

    return Finding(
        agent=AgentName.SAST,
        title=f"Hardcoded Secret Detected: {detector}",
        description=(
            f"A potential hardcoded {detector} secret was found in the source code. "
            "Hardcoded secrets are a critical security risk — they can be extracted "
            "from source code, version history, or compiled binaries."
        ),
        severity=Severity.CRITICAL,
        file_path=file_path,
        mitre_tactic="Credential Access",
        mitre_technique="T1552.001 — Credentials in Files",
        remediation=(
            "1. Immediately rotate the exposed credential. "
            "2. Move secrets to environment variables or a secrets manager (e.g. Azure Key Vault). "
            "3. Audit git history — if committed, the secret must be rotated even after removal. "
            "4. Add pre-commit hooks to prevent future secret commits."
        ),
        raw_output=json.dumps(hit),
    )
