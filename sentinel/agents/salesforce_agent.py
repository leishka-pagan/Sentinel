"""
sentinel/agents/salesforce_agent.py

Salesforce Experience Cloud Agent — Tier 1.
Part of PROBE mode agent suite.

Finds:
  - Exposed Salesforce REST API version endpoint (/services/data/)
  - Unauthenticated Apex REST endpoint accessibility (/services/apexrest/)
  - Unauthenticated community page enumeration
  - Guest user data access patterns

Salesforce Experience Cloud (formerly Community Cloud) frequently has
guest user profile misconfigurations — org admins grant more access than
intended to the Guest User profile, allowing unauthenticated data queries.

Scope: PROBE and ACTIVE modes only.
Actions: http_probe
NEVER: submits credentials, modifies data, runs SOQL, exploits anything.
All paths are standard Salesforce platform paths — not target-specific.
"""

import json as _json

from sentinel.core.models import AgentName, ScanSession, Finding, Severity
from sentinel.core.evidence import probe_with_evidence, safe_request
from sentinel.core.validator import validate_action

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
TIMEOUT = 12

# Standard Salesforce platform paths — applicable to any Experience Cloud instance
SF_API_PATHS = [
    "/services/data/",
    "/services/apexrest/",
]

# Common Experience Cloud community page paths
SF_COMMUNITY_PATHS = [
    "/s/",
    "/s/login/",
    "/s/profile",
    "/s/member",
    "/s/members",
    "/s/contact",
    "/s/contactsupport",
]

# Salesforce API version patterns in /services/data/ response
SF_VERSION_KEYS = ["version", "url", "label"]


def run_salesforce_agent(session: ScanSession, target_url: str) -> list[Finding]:
    """Run Salesforce Experience Cloud probing against a live target."""
    validate_action(AgentName.SALESFORCE, "http_probe", target_url, session)

    base = target_url.rstrip("/")
    findings = []

    findings.extend(_check_sf_api_endpoints(base))
    findings.extend(_check_community_pages(base))

    return findings


# ── Salesforce API Endpoints ──────────────────────────────────────────────────

def _check_sf_api_endpoints(base: str) -> list[Finding]:
    """
    Check standard Salesforce platform API paths.
    /services/data/ — lists available API versions (confirms API accessibility)
    /services/apexrest/ — lists exposed Apex REST resources if accessible
    """
    findings = []

    for path in SF_API_PATHS:
        url = base + path
        resp, artifact = probe_with_evidence(url, method="GET", auth_sent=False)

        if resp is None:
            continue

        status = resp.status_code

        if status in (401, 403, 404):
            continue

        if status == 200:
            er = artifact.response

            if path == "/services/data/":
                findings.extend(_assess_sf_data_endpoint(url, resp, er))
            elif path == "/services/apexrest/":
                findings.extend(_assess_sf_apexrest_endpoint(url, resp, er))

        elif status == 302:
            # Redirect — may indicate auth enforcement, note as INFO
            findings.append(Finding(
                agent=AgentName.SALESFORCE,
                title=f"Salesforce API Endpoint Redirects: {path}",
                description=(
                    f"{url} returned HTTP 302 — the endpoint exists and is "
                    "redirecting, likely to a login page. "
                    "This confirms the Salesforce platform is present."
                ),
                severity=Severity.INFO,
                file_path=url,
                mitre_tactic="Reconnaissance",
                mitre_technique="T1592 — Gather Victim Host Information",
                remediation="No action required — redirect indicates auth enforcement.",
            ))

    return findings


def _assess_sf_data_endpoint(url: str, resp, er) -> list[Finding]:
    """
    /services/data/ returns a JSON array of supported API versions.
    If accessible without auth, it confirms the Salesforce API surface
    and discloses version information.
    """
    try:
        data = resp.json()
    except (ValueError, _json.JSONDecodeError):
        return []

    if not isinstance(data, list) or len(data) == 0:
        return []

    # Extract version numbers from the response
    versions = []
    for item in data:
        if isinstance(item, dict):
            v = item.get("version") or item.get("label") or ""
            if v:
                versions.append(str(v))

    from sentinel.core.models import EvidenceRef
    ev = EvidenceRef(
        method="GET",
        url=url,
        status_code=resp.status_code,
        response_type=er.response_type,
        size_bytes=er.size_bytes,
        auth_sent=False,
        sensitive_fields=["version"] if versions else [],
        record_count=len(data),
        proof_snippet=er.sample,
    )

    ok, _ = ev.is_sufficient_for_confirmation()

    return [Finding(
        agent=AgentName.SALESFORCE,
        title="Salesforce REST API Version Endpoint Accessible",
        description=(
            f"Salesforce REST API version endpoint {url} is accessible without "
            f"authentication. "
            f"{len(data)} API version(s) enumerated. "
            + (f"Versions: {', '.join(versions[:5])}. " if versions else "")
            + "This confirms the Salesforce platform is present and discloses "
            "supported API version information that can be used for further probing."
        ),
        severity=Severity.LOW,
        file_path=url,
        evidence=ev if ok else None,
        mitre_tactic="Reconnaissance",
        mitre_technique="T1592 — Gather Victim Host Information",
        remediation=(
            "Restrict /services/data/ to authenticated users if possible, "
            "or accept this as informational disclosure — Salesforce platform "
            "presence is generally discoverable via other means."
        ),
    )]


def _assess_sf_apexrest_endpoint(url: str, resp, er) -> list[Finding]:
    """
    /services/apexrest/ lists exposed Apex REST resources.
    If accessible without auth, it may expose custom API endpoints
    that could have guest user access misconfigurations.
    """
    try:
        data = resp.json()
    except (ValueError, _json.JSONDecodeError):
        # Non-JSON 200 response — note the endpoint is accessible
        return [Finding(
            agent=AgentName.SALESFORCE,
            title="Salesforce Apex REST Endpoint Accessible (Non-JSON Response)",
            description=(
                f"Salesforce Apex REST endpoint {url} returned HTTP 200 without "
                "authentication but response was not JSON. "
                "The endpoint exists and is reachable — manual review recommended."
            ),
            severity=Severity.LOW,
            file_path=url,
            mitre_tactic="Reconnaissance",
            mitre_technique="T1592 — Gather Victim Host Information",
            remediation=(
                "Review Apex REST class sharing settings and Guest User profile "
                "permissions to ensure unauthenticated access is intentional."
            ),
        )]

    # JSON response — enumerate exposed resources
    resources = []
    if isinstance(data, list):
        resources = [str(item) for item in data[:20] if item]
    elif isinstance(data, dict):
        resources = list(data.keys())[:20]

    severity = Severity.MEDIUM if resources else Severity.LOW

    from sentinel.core.models import EvidenceRef
    ev = EvidenceRef(
        method="GET",
        url=url,
        status_code=resp.status_code,
        response_type=er.response_type,
        size_bytes=er.size_bytes,
        auth_sent=False,
        sensitive_fields=[],
        record_count=len(resources) if resources else None,
        proof_snippet=er.sample,
    )

    ok, _ = ev.is_sufficient_for_confirmation()

    return [Finding(
        agent=AgentName.SALESFORCE,
        title="Salesforce Apex REST Resources Exposed Without Auth",
        description=(
            f"Salesforce Apex REST endpoint {url} returned a JSON response "
            f"without authentication. "
            + (f"Exposed resources: {', '.join(resources[:10])}. " if resources else "")
            + "Exposed Apex REST resources may allow unauthenticated data access "
            "if the Guest User profile has been granted access to these classes."
        ),
        severity=severity,
        file_path=url,
        evidence=ev if ok else None,
        mitre_tactic="Initial Access",
        mitre_technique="T1190 — Exploit Public-Facing Application",
        remediation=(
            "Audit Apex REST class sharing settings. "
            "Ensure Guest User profile does not have access to sensitive Apex classes. "
            "Use 'without sharing' carefully — it bypasses record-level security."
        ),
    )]


# ── Community Page Enumeration ────────────────────────────────────────────────

def _check_community_pages(base: str) -> list[Finding]:
    """
    Probe standard Experience Cloud community paths.
    Checks whether unauthenticated users can access pages that should
    require authentication — common misconfiguration in Experience Cloud.
    """
    findings = []
    accessible_pages = []
    login_pages = []

    for path in SF_COMMUNITY_PATHS:
        url = base + path
        resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                            allow_redirects=True)
        if resp is None:
            continue

        status = resp.status_code
        content = resp.text if hasattr(resp, "text") else ""
        content_lower = content.lower()
        final_url = resp.url if hasattr(resp, "url") else url

        if status == 200:
            # Check if the page is actually a login form or a real content page
            is_login = (
                "login" in content_lower[:2000] and
                ("password" in content_lower[:2000] or
                 "sign in" in content_lower[:2000])
            )
            is_redirected_to_login = "/login" in final_url.lower()

            if is_login or is_redirected_to_login:
                login_pages.append(path)
            else:
                # Real content page accessible without auth
                size = len(content)
                accessible_pages.append((path, size))

        elif status in (302, 301):
            # Redirect — check where it goes
            location = resp.headers.get("Location", "") if hasattr(resp, "headers") else ""
            if "/login" in location.lower():
                login_pages.append(path)

    if accessible_pages:
        page_list = ", ".join(
            f"{p} ({s}b)" for p, s in accessible_pages[:10]
        )
        findings.append(Finding(
            agent=AgentName.SALESFORCE,
            title="Salesforce Experience Cloud Pages Accessible Without Login",
            description=(
                f"The following Experience Cloud community pages returned content "
                f"without requiring authentication: {page_list}. "
                "If these pages contain member-only information or functionality, "
                "this may indicate a Guest User profile misconfiguration."
            ),
            severity=Severity.MEDIUM,
            file_path=base + accessible_pages[0][0],
            mitre_tactic="Initial Access",
            mitre_technique="T1190 — Exploit Public-Facing Application",
            remediation=(
                "Review Experience Cloud page visibility settings. "
                "Ensure pages intended for authenticated members are not accessible "
                "to guest users. Audit the Guest User profile permissions in Salesforce Setup."
            ),
        ))

    if login_pages:
        findings.append(Finding(
            agent=AgentName.SALESFORCE,
            title="Salesforce Experience Cloud Login Page Confirmed",
            description=(
                f"Experience Cloud login page confirmed at: "
                f"{', '.join(login_pages[:5])}. "
                "Authentication is enforced on these paths."
            ),
            severity=Severity.INFO,
            file_path=base + login_pages[0],
            mitre_tactic="Reconnaissance",
            mitre_technique="T1592 — Gather Victim Host Information",
            remediation="No action required — login enforcement is working as expected.",
        ))

    return findings
