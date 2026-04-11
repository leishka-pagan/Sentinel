"""
sentinel/agents/wordpress_agent.py

WordPress REST API Agent — Tier 1.
Part of PROBE mode agent suite.

Finds:
  - User enumeration via /wp-json/wp/v2/users (names, slugs, links exposed)
  - Content exposure via /wp-json/wp/v2/posts and /wp-json/wp/v2/pages
  - WordPress REST API accessibility and version information

Rate-aware: on HTTP 429, waits RETRY_DELAY_SECONDS once then retries.
If the retry also returns 429, records INCONCLUSIVE and moves on.
Never hammers a rate-limited endpoint.

Scope: PROBE and ACTIVE modes only.
Actions: http_probe
NEVER: submits credentials, modifies data, brute forces, exploits anything.
All paths are standard WordPress REST API paths — not target-specific.
"""

import time
import json as _json

from sentinel.core.models import AgentName, ScanSession, Finding, Severity
from sentinel.core.evidence import probe_with_evidence
from sentinel.core.validator import validate_action

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
TIMEOUT = 12
RETRY_DELAY_SECONDS = 5  # Wait before single retry on 429 — not a loop

# Standard WordPress REST API endpoints — applicable to any WP install
WP_REST_ENDPOINTS = [
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
]


def run_wordpress_agent(session: ScanSession, target_url: str) -> list[Finding]:
    """Run WordPress REST API probing against a live target."""
    validate_action(AgentName.WORDPRESS, "http_probe", target_url, session)

    base = target_url.rstrip("/")
    findings = []

    for endpoint in WP_REST_ENDPOINTS:
        url = base + endpoint
        resp, artifact = _probe_with_retry(url)

        if resp is None:
            continue

        status = resp.status_code

        if status == 429:
            # Both initial and retry returned 429 — WAF/rate limiting active
            findings.append(Finding(
                agent=AgentName.WORDPRESS,
                title=f"WordPress REST API Rate Limited: {endpoint}",
                description=(
                    f"Requests to {url} returned HTTP 429 (Too Many Requests) "
                    f"even after a {RETRY_DELAY_SECONDS}-second delay. "
                    "A WAF or rate limiting mechanism is protecting this endpoint. "
                    "This is a positive security signal — the API is not freely accessible."
                ),
                severity=Severity.INFO,
                file_path=url,
                mitre_tactic="Discovery",
                mitre_technique="T1595 — Active Scanning",
                remediation="No action required — rate limiting is working as intended.",
            ))
            continue

        if status in (401, 403):
            # Authentication enforced — good signal, no finding needed
            continue

        if status == 404:
            # REST API not present or disabled at this path
            continue

        if status == 200:
            er = artifact.response
            if er.response_type != "JSON":
                continue

            if endpoint == "/wp-json/wp/v2/users":
                findings.extend(_assess_users_endpoint(url, resp, er))
            elif endpoint in ("/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages"):
                findings.extend(_assess_content_endpoint(url, endpoint, resp, er))

    return findings


# ── Rate-aware probe ──────────────────────────────────────────────────────────

def _probe_with_retry(url: str):
    """
    Probe with a single 429-aware retry.
    On 429: wait RETRY_DELAY_SECONDS, retry once.
    On second 429: return the 429 response — caller decides.
    On network failure: return (None, None).
    """
    resp, artifact = probe_with_evidence(url, method="GET", auth_sent=False)

    if resp is None:
        return None, None

    if resp.status_code == 429:
        print(f"[WP] 429 on {url} — waiting {RETRY_DELAY_SECONDS}s before retry")
        time.sleep(RETRY_DELAY_SECONDS)
        resp, artifact = probe_with_evidence(url, method="GET", auth_sent=False)
        if resp is None:
            return None, None

    return resp, artifact


# ── Endpoint assessors ────────────────────────────────────────────────────────

def _assess_users_endpoint(url: str, resp, er) -> list[Finding]:
    """
    Assess /wp-json/wp/v2/users — user enumeration finding.
    A JSON list response here means WordPress is exposing usernames, slugs,
    and profile links without authentication.
    """
    findings = []

    try:
        data = resp.json()
    except (ValueError, _json.JSONDecodeError):
        return []

    if not isinstance(data, list) or len(data) == 0:
        return []

    # Extract disclosed usernames and slugs
    names = []
    for user in data[:20]:  # Cap at 20 — sufficient to prove the issue
        if isinstance(user, dict):
            name = user.get("name") or user.get("slug") or user.get("link", "")
            if name:
                names.append(str(name))

    user_count = er.record_count if er.record_count is not None else len(data)

    from sentinel.core.models import EvidenceRef
    ev = EvidenceRef(
        method="GET",
        url=url,
        status_code=resp.status_code,
        response_type=er.response_type,
        size_bytes=er.size_bytes,
        auth_sent=False,
        sensitive_fields=["name", "slug", "link"] if names else [],
        record_count=user_count,
        proof_snippet=er.sample,
    )

    ok, _ = ev.is_sufficient_for_confirmation()

    findings.append(Finding(
        agent=AgentName.WORDPRESS,
        title="WordPress REST API User Enumeration",
        description=(
            f"WordPress REST API endpoint {url} returns user account information "
            f"without authentication. "
            f"{user_count} user(s) enumerated. "
            + (f"Disclosed: {', '.join(names[:5])}" + (" ..." if len(names) > 5 else "") + ". "
               if names else "")
            + "Exposed fields typically include username, display name, slug, and profile link. "
            "This information can be used in credential attacks against /wp-login.php "
            "or the REST API login endpoint."
        ),
        severity=Severity.MEDIUM,
        file_path=url,
        evidence=ev if ok else None,
        mitre_tactic="Reconnaissance",
        mitre_technique="T1589.001 — Gather Victim Identity Information: Credentials",
        remediation=(
            "Disable the /wp-json/wp/v2/users endpoint for unauthenticated users "
            "by adding a REST API permission callback, or use a security plugin "
            "to restrict REST API access to authenticated users only."
        ),
    ))

    return findings


def _assess_content_endpoint(url: str, endpoint: str, resp, er) -> list[Finding]:
    """
    Assess /wp-json/wp/v2/posts and /wp-json/wp/v2/pages.
    A large JSON list here reveals content metadata — titles, authors, dates,
    slugs, and sometimes draft content.
    """
    try:
        data = resp.json()
    except (ValueError, _json.JSONDecodeError):
        return []

    if not isinstance(data, list) or len(data) == 0:
        return []

    resource = "posts" if "posts" in endpoint else "pages"
    record_count = er.record_count if er.record_count is not None else len(data)

    # Check if any non-published content is exposed
    statuses = set()
    for item in data[:20]:
        if isinstance(item, dict):
            status = item.get("status", "")
            if status:
                statuses.add(status)

    has_non_public = any(s not in ("publish", "published") for s in statuses)

    severity = Severity.MEDIUM if has_non_public else Severity.INFO

    description = (
        f"WordPress REST API endpoint {url} returns {resource} metadata "
        f"without authentication. "
        f"{record_count} {resource} enumerated. "
        f"Response includes titles, slugs, author IDs, publish dates, and content excerpts. "
    )
    if has_non_public:
        description += (
            f"Non-published content statuses detected: {', '.join(sorted(statuses))}. "
            "Draft or private content may be accessible."
        )

    return [Finding(
        agent=AgentName.WORDPRESS,
        title=f"WordPress REST API Content Enumeration: {resource}",
        description=description,
        severity=severity,
        file_path=url,
        mitre_tactic="Reconnaissance",
        mitre_technique="T1592 — Gather Victim Host Information",
        remediation=(
            f"If {resource} metadata should not be publicly accessible, restrict "
            "the REST API to authenticated users only. "
            "Review whether draft or private content is unintentionally exposed."
        ),
    )]
