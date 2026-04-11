"""
sentinel/agents/wordpress_enum_agent.py

WordPress Path Enumeration Agent.
Part of Tier 1 — general WordPress enumeration applicable to any WP target.

Finds:
  - WordPress author username disclosure via /?author=N redirects
  - xmlrpc.php accessibility (historically exploited for credential stuffing)
  - wp-cron.php public accessibility (can be abused to trigger server-side jobs)
  - sitemap.xml / sitemap_index.xml — page count and structural exposure
  - robots.txt Disallow: entries as a roadmap to sensitive paths

Scope: PROBE and ACTIVE modes only.
Actions: http_probe
NEVER: submits credentials, modifies data, brute forces, exploits anything.
All paths tested are standard WordPress platform paths — not target-specific.
"""

from sentinel.core.models import AgentName, ScanSession, Finding, Severity
from sentinel.core.evidence import safe_request
from sentinel.core.validator import validate_action

HEADERS = {"User-Agent": "Sentinel-SecurityScanner/1.0"}
TIMEOUT = 10

# Author IDs to test — standard enumeration range, not target-specific
AUTHOR_IDS = [1, 2, 3, 4, 5]

# WordPress platform paths — general, applicable to any WP install
WP_PLATFORM_PATHS = [
    "/xmlrpc.php",
    "/wp-cron.php",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/robots.txt",
]


def run_wordpress_enum_agent(session: ScanSession, target_url: str) -> list[Finding]:
    """Run WordPress path enumeration against a live target."""
    validate_action(AgentName.WP_ENUM, "http_probe", target_url, session)

    base = target_url.rstrip("/")
    findings = []

    findings.extend(_check_author_enumeration(base))
    findings.extend(_check_wp_platform_paths(base))

    return findings


# ── Author Enumeration ────────────────────────────────────────────────────────

def _check_author_enumeration(base: str) -> list[Finding]:
    """
    Test /?author=N for username disclosure via redirect.
    WordPress redirects /?author=1 to /author/username/ by default.
    That redirect reveals the username — information disclosure.
    """
    findings = []
    disclosed_users = []

    for author_id in AUTHOR_IDS:
        url = f"{base}/?author={author_id}"
        resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                            allow_redirects=True)
        if resp is None:
            continue

        # WordPress redirects to /author/<username>/ — extract username from final URL
        final_url = resp.url if hasattr(resp, "url") else url

        if "/author/" in final_url and resp.status_code == 200:
            # Extract username from path: /author/username/ or /author/username/page/N/
            parts = final_url.split("/author/")
            if len(parts) > 1:
                username = parts[1].split("/")[0].strip()
                if username and username not in disclosed_users:
                    disclosed_users.append(username)

    if disclosed_users:
        findings.append(Finding(
            agent=AgentName.WP_ENUM,
            title="WordPress Author Username Disclosure",
            description=(
                f"WordPress author enumeration via /?author=N redirects disclosed "
                f"{len(disclosed_users)} username(s): {', '.join(disclosed_users)}. "
                f"Usernames can be used in credential attacks against /wp-login.php "
                f"or brute-forced against the WordPress REST API. "
                f"Tested IDs: {AUTHOR_IDS}."
            ),
            severity=Severity.MEDIUM,
            file_path=base + "/?author=1",
            mitre_tactic="Reconnaissance",
            mitre_technique="T1589.001 — Gather Victim Identity Information: Credentials",
            remediation=(
                "Install a plugin to disable author enumeration redirects "
                "(e.g. Yoast SEO has this option), or add a rewrite rule to "
                "redirect /?author=N requests to the homepage."
            ),
        ))
    elif any(
        safe_request("GET", f"{base}/?author={i}", headers=HEADERS,
                     timeout=TIMEOUT, allow_redirects=False) is not None
        for i in AUTHOR_IDS[:1]
    ):
        # Endpoint responds but no username disclosed — informational
        findings.append(Finding(
            agent=AgentName.WP_ENUM,
            title="WordPress Author Enumeration: No Username Disclosed",
            description=(
                "WordPress author enumeration via /?author=N was tested but no "
                "usernames were disclosed via redirects. "
                "Author enumeration may be disabled or redirects are suppressed."
            ),
            severity=Severity.INFO,
            file_path=base + "/?author=1",
            mitre_tactic="Reconnaissance",
            mitre_technique="T1589.001 — Gather Victim Identity Information: Credentials",
            remediation="No action required — author enumeration appears mitigated.",
        ))

    return findings


# ── WordPress Platform Paths ──────────────────────────────────────────────────

def _check_wp_platform_paths(base: str) -> list[Finding]:
    """Check standard WordPress platform paths for accessibility and content."""
    findings = []

    for path in WP_PLATFORM_PATHS:
        url = base + path
        resp = safe_request("GET", url, headers=HEADERS, timeout=TIMEOUT,
                            allow_redirects=False)
        if resp is None:
            continue

        status = resp.status_code

        if path == "/xmlrpc.php":
            findings.extend(_assess_xmlrpc(url, status, resp))

        elif path == "/wp-cron.php":
            findings.extend(_assess_wp_cron(url, status))

        elif path in ("/sitemap.xml", "/sitemap_index.xml"):
            findings.extend(_assess_sitemap(url, path, status, resp))

        elif path == "/robots.txt":
            findings.extend(_assess_robots(url, status, resp))

    return findings


def _assess_xmlrpc(url: str, status: int, resp) -> list[Finding]:
    """Assess xmlrpc.php accessibility."""
    if status == 200:
        content = resp.text if hasattr(resp, "text") else ""
        # xmlrpc.php returns XML with "XML-RPC server accepts POST requests only"
        # when accessible
        is_active = (
            "xml-rpc" in content.lower() or
            "xmlrpc" in content.lower() or
            "post requests" in content.lower()
        )
        return [Finding(
            agent=AgentName.WP_ENUM,
            title="WordPress xmlrpc.php Accessible",
            description=(
                f"WordPress XML-RPC endpoint is publicly accessible at {url}. "
                + ("Response confirms XML-RPC is active. " if is_active else "")
                + "xmlrpc.php has historically been used for credential stuffing "
                "(system.multicall allows thousands of login attempts in a single request), "
                "DDoS amplification, and content manipulation. "
                "Unless required for Jetpack or mobile app publishing, it should be disabled."
            ),
            severity=Severity.MEDIUM,
            file_path=url,
            mitre_tactic="Initial Access",
            mitre_technique="T1190 — Exploit Public-Facing Application",
            remediation=(
                "Disable xmlrpc.php via .htaccess or a security plugin if not required. "
                "If required for Jetpack, use a plugin to block system.multicall specifically."
            ),
        )]
    return []


def _assess_wp_cron(url: str, status: int) -> list[Finding]:
    """Assess wp-cron.php public accessibility."""
    if status == 200:
        return [Finding(
            agent=AgentName.WP_ENUM,
            title="WordPress wp-cron.php Publicly Accessible",
            description=(
                f"WordPress cron endpoint wp-cron.php is publicly accessible at {url}. "
                "External requests to this file trigger scheduled WordPress tasks. "
                "This can be abused to cause excessive server load by repeatedly "
                "triggering cron jobs from external IPs."
            ),
            severity=Severity.MEDIUM,
            file_path=url,
            mitre_tactic="Impact",
            mitre_technique="T1499 — Endpoint Denial of Service",
            remediation=(
                "Disable wp-cron.php public access by adding "
                "define('DISABLE_WP_CRON', true) to wp-config.php and "
                "scheduling a real server-side cron job instead."
            ),
        )]
    return []


def _assess_sitemap(url: str, path: str, status: int, resp) -> list[Finding]:
    """Assess sitemap exposure."""
    if status != 200:
        return []

    content = resp.text if hasattr(resp, "text") else ""
    # Count URLs or sub-sitemaps
    url_count = content.lower().count("<url>")
    sitemap_count = content.lower().count("<sitemap>")

    description = (
        f"WordPress sitemap found at {url}. "
    )
    if url_count:
        description += f"Contains {url_count} indexed URL(s). "
    if sitemap_count:
        description += f"References {sitemap_count} sub-sitemap(s). "
    description += (
        "Sitemaps enumerate all publicly indexed pages including "
        "potentially sensitive paths not linked elsewhere."
    )

    return [Finding(
        agent=AgentName.WP_ENUM,
        title=f"WordPress Sitemap Exposed: {path}",
        description=description,
        severity=Severity.INFO,
        file_path=url,
        mitre_tactic="Reconnaissance",
        mitre_technique="T1592 — Gather Victim Host Information",
        remediation=(
            "Review sitemap contents to ensure no sensitive or unintended paths "
            "are indexed. Restrict sitemap access if the site is not intended for "
            "public indexing."
        ),
    )]


def _assess_robots(url: str, status: int, resp) -> list[Finding]:
    """Assess robots.txt — extract Disallow entries as a path roadmap."""
    if status != 200:
        return []

    content = resp.text if hasattr(resp, "text") else ""
    disallow_paths = []
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                disallow_paths.append(path)

    if not disallow_paths:
        return [Finding(
            agent=AgentName.WP_ENUM,
            title="robots.txt Found (No Sensitive Disallow Entries)",
            description=(
                f"robots.txt is accessible at {url} but contains no "
                "specific Disallow entries that reveal sensitive paths."
            ),
            severity=Severity.INFO,
            file_path=url,
            mitre_tactic="Reconnaissance",
            mitre_technique="T1592 — Gather Victim Host Information",
            remediation="No action required.",
        )]

    # Sensitive keywords that warrant MEDIUM severity
    sensitive_keywords = ["admin", "login", "backup", "config", "private",
                          "staging", "test", "dev", "api", "secret"]
    sensitive_paths = [
        p for p in disallow_paths
        if any(kw in p.lower() for kw in sensitive_keywords)
    ]
    severity = Severity.MEDIUM if sensitive_paths else Severity.INFO

    description = (
        f"robots.txt at {url} contains {len(disallow_paths)} Disallow "
        f"entr{'y' if len(disallow_paths) == 1 else 'ies'}: "
        f"{', '.join(disallow_paths[:10])}"
        + (" ..." if len(disallow_paths) > 10 else "") + ". "
    )
    if sensitive_paths:
        description += (
            f"The following paths contain sensitive keywords and should be reviewed: "
            f"{', '.join(sensitive_paths[:5])}."
        )

    return [Finding(
        agent=AgentName.WP_ENUM,
        title="robots.txt Discloses Sensitive Path Structure",
        description=description,
        severity=severity,
        file_path=url,
        mitre_tactic="Reconnaissance",
        mitre_technique="T1592 — Gather Victim Host Information",
        remediation=(
            "Review robots.txt Disallow entries to ensure they do not map out "
            "sensitive internal paths. Obscuring paths in robots.txt provides "
            "no security — these paths should be protected by access controls, "
            "not by omission from robots.txt."
        ),
    )]
