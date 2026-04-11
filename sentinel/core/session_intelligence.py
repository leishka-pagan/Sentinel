"""
sentinel/core/session_intelligence.py

SessionIntelligence — The authoritative source of truth for a scan session.

This is not a notes bucket. It is a structured, enforcement-capable memory layer.

Roles:
  1. Memory layer        — everything observed, confirmed, refuted, learned
  2. Deduplication layer — no URL probed twice, no finding created twice
  3. Coordination layer  — Queen and Alpha share this, see same state
  4. Promotion context   — scoring engine reads this to calibrate confidence
  5. Budget enforcer     — tracks and enforces request limits
  6. Stop condition mgr  — defines when investigation is genuinely complete

Every endpoint record contains:
  - What was tested (method, URL, timestamp)
  - What happened (status, type, size, auth behavior)
  - What it means (CONFIRMED / DISPROVEN / INCONCLUSIVE)
  - Why it was classified that way (specific reason)
  - What to do next (retest policy)
  - Full evidence object reference
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum


# ── State definitions ─────────────────────────────────────────────────────────

class ProbeOutcome(str, Enum):
    CONFIRMED    = "CONFIRMED"     # Vulnerable — full evidence attached
    DISPROVEN    = "DISPROVEN"     # NOT vulnerable — reason documented
    INCONCLUSIVE = "INCONCLUSIVE"  # Tested but ambiguous
    UNTESTED     = "UNTESTED"      # Not yet probed


class DisproveReason(str, Enum):
    AUTH_ENFORCED    = "AUTH_ENFORCED"    # 401/403 — access control working
    SPA_FALLBACK     = "SPA_FALLBACK"     # HTML SPA shell, no server data
    NOT_FOUND        = "NOT_FOUND"        # 404 — endpoint doesn't exist
    EMPTY_RESPONSE   = "EMPTY_RESPONSE"   # 200 but < 200 bytes
    SERVER_ERROR     = "SERVER_ERROR"     # 500 — broken but not vulnerable
    NO_RESPONSE      = "NO_RESPONSE"      # Timeout or connection refused
    WRONG_FORMAT     = "WRONG_FORMAT"     # Response format unexpected


class RetestPolicy(str, Enum):
    NEVER          = "NEVER"           # Do not probe again under any condition
    IF_AUTH_ADDED  = "IF_AUTH_ADDED"   # Only retry if auth token available
    IF_DIFFERENT_METHOD = "IF_DIFFERENT_METHOD"  # Try a different HTTP method
    AFTER_N_CYCLES = "AFTER_N_CYCLES"  # Can retry after 3+ cycles
    ALWAYS_SKIP    = "ALWAYS_SKIP"     # SPA fallback — skip completely


class AuthBehavior(str, Enum):
    REQUIRES_AUTH   = "REQUIRES_AUTH"    # Returns 401/403 without token
    NO_AUTH_NEEDED  = "NO_AUTH_NEEDED"   # Returns data without auth
    AUTH_IRRELEVANT = "AUTH_IRRELEVANT"  # SPA / static content
    UNKNOWN         = "UNKNOWN"          # Not yet determined


class StopCondition(str, Enum):
    BUDGET_EXHAUSTED      = "BUDGET_EXHAUSTED"
    ALL_PATHS_SETTLED     = "ALL_PATHS_SETTLED"   # Every path confirmed or disproven
    MAX_CYCLES_REACHED    = "MAX_CYCLES_REACHED"
    MANUAL_STOP           = "MANUAL_STOP"
    SUFFICIENT_EVIDENCE   = "SUFFICIENT_EVIDENCE"  # Enough to write report


# ── Core data structures ──────────────────────────────────────────────────────

@dataclass
class EvidenceRef:
    """Structured evidence object — not a summary string."""
    method:          str
    url:             str
    status_code:     int
    response_type:   str              # JSON | HTML | TEXT | EMPTY
    size_bytes:      int
    auth_sent:       bool
    sensitive_fields: list[str]
    record_count:    Optional[int]
    proof_snippet:   Optional[str]    # Sanitized sample — required for CONFIRMED
    timestamp:       str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def is_sufficient_for_confirmation(self) -> tuple[bool, str]:
        """Hard check — is this evidence good enough to CONFIRM a finding?"""
        if self.status_code != 200:
            return False, f"HTTP {self.status_code} — only 200 confirms"
        if self.response_type == "HTML":
            return False, "HTML response — not structured data"
        if self.response_type == "EMPTY":
            return False, "Empty response — no evidence"
        if self.size_bytes < 200:
            return False, f"Too small ({self.size_bytes}b)"
        if not self.proof_snippet:
            return False, "No proof snippet — required"
        if self.auth_sent:
            return False, "Auth was sent — cannot confirm auth bypass"
        return True, "OK"

    def format(self) -> str:
        auth_str = "YES — 401/403" if self.status_code in (401, 403) else \
                   "NOT required" if not self.auth_sent and self.status_code == 200 else \
                   "unknown"
        parts = [
            f"Request:  {self.method} {self.url}",
            f"Status:   {self.status_code}",
            f"Type:     {self.response_type} ({self.size_bytes}b)",
            f"Auth req: {auth_str}",
        ]
        if self.record_count is not None:
            parts.append(f"Records:  {self.record_count}")
        if self.sensitive_fields:
            parts.append(f"Sensitive: {', '.join(self.sensitive_fields[:4])}")
        if self.proof_snippet:
            parts.append(f"Proof:    {self.proof_snippet[:150]}")
        return "\n".join(parts)


@dataclass
class EndpointRecord:
    """
    Complete record for a single endpoint.
    This is the unit of session intelligence — not a string, a structured object.
    """
    url:             str
    outcome:         ProbeOutcome
    auth_behavior:   AuthBehavior
    evidence:        Optional[EvidenceRef]
    disprove_reason: Optional[DisproveReason]
    retest_policy:   RetestPolicy
    classification_reason: str        # Why it was classified this way
    cycle_discovered: int
    confidence:      float = 0.0      # Confidence in the outcome
    chain_candidate: bool = False     # Could this be part of an attack chain?
    related_endpoints: list[str] = field(default_factory=list)

    def format_short(self) -> str:
        icon = "✅" if self.outcome == ProbeOutcome.CONFIRMED else \
               "❌" if self.outcome == ProbeOutcome.DISPROVEN else \
               "🔍" if self.outcome == ProbeOutcome.INCONCLUSIVE else "❓"
        return (f"{icon} {self.url} [{self.outcome.value}] "
                f"— {self.classification_reason[:60]}")

    def format_full(self) -> str:
        lines = [
            f"Endpoint:     {self.url}",
            f"Outcome:      {self.outcome.value}",
            f"Auth:         {self.auth_behavior.value}",
            f"Reason:       {self.classification_reason}",
            f"Retest:       {self.retest_policy.value}",
            f"Confidence:   {self.confidence:.2f}",
            f"Chain cand:   {self.chain_candidate}",
        ]
        if self.disprove_reason:
            lines.append(f"Disproved:    {self.disprove_reason.value}")
        if self.evidence:
            lines.append(f"\nEvidence:\n{self.evidence.format()}")
        return "\n".join(lines)


@dataclass
class ChainCandidate:
    """
    A potential attack chain — confirmed findings that could link together.
    Only built from CONFIRMED endpoints.
    """
    candidate_id: str
    title:        str
    endpoints:    list[str]         # CONFIRMED endpoints in this path
    confidence:   float
    severity:     str
    evidence_count: int = 0
    promoted:     bool = False      # Has this been promoted to a full chain?


@dataclass
class LearnedBehavior:
    """Structured behavioral knowledge — not free text."""
    namespace:   str       # e.g. "/api/", "/rest/admin/"
    auth_pattern: AuthBehavior
    url_pattern: str       # e.g. "Capitalize resource names"
    examples:    list[str] = field(default_factory=list)
    confidence:  float = 0.5
    discovered_at: int = 0


@dataclass
class RootCause:
    """Multiple endpoints with the same underlying vulnerability."""
    root_id:     str
    title:       str
    category:    str
    pattern:     str
    severity:    str
    endpoints:   list[str] = field(default_factory=list)
    evidence_count: int = 0
    next_action: str = ""
    verified:    bool = False


# ── Session Intelligence ──────────────────────────────────────────────────────

class SessionIntelligence:
    """
    The authoritative source of truth for the entire scan session.

    Roles:
      1. Memory layer         — everything observed, confirmed, refuted
      2. Deduplication layer  — no URL probed twice
      3. Coordination layer   — Queen and Alpha share this
      4. Promotion context    — calibrates confidence scoring
      5. Budget enforcer      — tracks and limits request counts
      6. Stop condition mgr   — knows when to stop
    """

    # Budget defaults per mode
    BUDGETS = {
        "PASSIVE": 50,
        "PROBE":   300,
        "ACTIVE":  600,
        "AUDIT":   400,
    }

    def __init__(self, target: str, mode: str = "PROBE"):
        self.target       = target
        self.mode         = mode
        self.session_id   = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.started_at   = datetime.now(timezone.utc).isoformat()
        self.current_cycle = 0

        # ── Core memory stores ────────────────────────────────────────────────
        # Keyed by URL for O(1) lookup
        self.endpoints:  dict[str, EndpointRecord] = {}

        # Indexed views for fast access
        self.confirmed_urls:    set[str] = set()
        self.disproven_urls:    set[str] = set()
        self.inconclusive_urls: set[str] = set()

        # ── Behavioral intelligence ───────────────────────────────────────────
        self.behaviors:  list[LearnedBehavior] = []
        self.root_causes: list[RootCause] = []
        self.chain_candidates: list[ChainCandidate] = []

        # ── Coordination ──────────────────────────────────────────────────────
        self.queen_objectives_completed: list[str] = []
        self.queen_objectives_failed:    list[str] = []
        self.alpha_cycles_used:          int = 0

        # ── Budget tracking ───────────────────────────────────────────────────
        self.budget_total:     int = self.BUDGETS.get(mode, 300)
        self.budget_used:      int = 0
        self.budget_by_domain: dict[str, int] = {}

        # ── Stop conditions ───────────────────────────────────────────────────
        self.stop_condition:   Optional[StopCondition] = None
        self.stop_triggered:   bool = False

        # ── Statistics ────────────────────────────────────────────────────────
        self.probes_prevented: int = 0   # Reprobe attempts blocked
        self.hallucinations_blocked: int = 0
        self.duplicates_removed: int = 0
        self.untested_queue:   list[str] = []  # Endpoints discovered by agents, queued for Alpha
        self.inconclusive_counts: dict[str, int] = {}  # How many times each URL returned inconclusive

        # Attack graph — drives chain-based investigation
        from sentinel.core.attack_graph import AttackGraph
        self.attack_graph: AttackGraph = AttackGraph()

    # ── Core probe lifecycle ──────────────────────────────────────────────────

    def should_probe(self, url: str) -> tuple[bool, str]:
        """
        The central guard. Called before EVERY probe.
        Returns (should_probe, reason_if_not).

        This makes loops structurally impossible.
        """
        # Budget check first
        if self.budget_used >= self.budget_total:
            self.stop_triggered = True
            self.stop_condition = StopCondition.BUDGET_EXHAUSTED
            return False, f"Budget exhausted ({self.budget_used}/{self.budget_total})"

        # Stop condition check
        if self.stop_triggered:
            return False, f"Stop condition: {self.stop_condition.value}"

        # Known outcome checks
        if url in self.confirmed_urls:
            self.probes_prevented += 1
            ep = self.endpoints.get(url)
            return False, f"CONFIRMED — skip (evidence: {ep.evidence.proof_snippet[:40] if ep and ep.evidence else 'captured'})"

        if url in self.disproven_urls:
            self.probes_prevented += 1
            ep = self.endpoints.get(url)
            reason = ep.disprove_reason.value if ep and ep.disprove_reason else "disproven"
            retest = ep.retest_policy.value if ep else "NEVER"
            if retest == RetestPolicy.NEVER.value or retest == RetestPolicy.ALWAYS_SKIP.value:
                return False, f"DISPROVEN ({reason}) — retest policy: {retest}"
            # Some policies allow retry
            if retest == RetestPolicy.IF_AUTH_ADDED.value:
                return False, f"DISPROVEN ({reason}) — retry only with auth token"

        if url in self.inconclusive_urls:
            count = self.inconclusive_counts.get(url, 0)
            if count >= 2:
                # Hard stop — probed twice, both inconclusive, not worth retrying
                self.probes_prevented += 1
                return False, f"INCONCLUSIVE x{count} — hard stop after 2 attempts"
            ep = self.endpoints.get(url)
            if ep and ep.cycle_discovered >= self.current_cycle - 1:
                self.probes_prevented += 1
                return False, f"INCONCLUSIVE — too recent to retry (cycle {ep.cycle_discovered})"

        return True, "Proceed"

    def record_confirmed(self, url: str, evidence: EvidenceRef,
                         confidence: float = 0.85) -> EndpointRecord:
        """Register a confirmed finding with full evidence."""
        # Validate evidence before accepting CONFIRMED state
        ok, reason = evidence.is_sufficient_for_confirmation()
        if not ok:
            # Auto-downgrade to INCONCLUSIVE
            print(f"[INTEL] ⚠ Cannot CONFIRM {url}: {reason} — downgrading to INCONCLUSIVE")
            return self.record_inconclusive(url, evidence, f"Evidence insufficient: {reason}")

        ep = EndpointRecord(
            url=url,
            outcome=ProbeOutcome.CONFIRMED,
            auth_behavior=AuthBehavior.NO_AUTH_NEEDED,
            evidence=evidence,
            disprove_reason=None,
            retest_policy=RetestPolicy.NEVER,
            classification_reason=(
                f"HTTP {evidence.status_code} | {evidence.response_type} | "
                f"{evidence.size_bytes}b | no auth sent"
                + (f" | {evidence.record_count} records" if evidence.record_count else "")
                + (f" | sensitive: {','.join(evidence.sensitive_fields[:2])}" if evidence.sensitive_fields else "")
            ),
            cycle_discovered=self.current_cycle,
            confidence=confidence,
            chain_candidate=True,  # Confirmed findings are chain candidates
        )
        self.endpoints[url] = ep
        self.confirmed_urls.add(url)
        self.budget_used += 1
        # Remove from untested queue if present
        if url in self.untested_queue:
            self.untested_queue.remove(url)
        self._update_root_cause(url, evidence)
        self._evaluate_chain_candidates()
        self._check_stop_conditions()

        # Fire attack graph — chain-based next steps go to FRONT of queue
        next_steps = self.attack_graph.record_confirmed(
            url=url,
            evidence_summary=evidence.proof_snippet or evidence.format()[:100],
            session_intel=self,
        )
        if next_steps:
            for step_url in reversed(next_steps):
                if (step_url not in self.confirmed_urls and
                        step_url not in self.disproven_urls and
                        self.inconclusive_counts.get(step_url, 0) < 2 and
                        step_url not in self.untested_queue):
                    self.untested_queue.insert(0, step_url)
            print(f"[CHAIN] Queued {len(next_steps)} chain-driven next steps at queue front")

        # Notify eval harness of first confirmed finding (for time-to-confirm metric)
        try:
            import sentinel.agents._eval_ref as _eref
            harness = getattr(_eref, 'current_harness', None)
            if harness:
                harness.record_first_confirmed()
        except Exception:
            pass

        return ep

    def record_disproven(self, url: str, reason: DisproveReason,
                         evidence: Optional[EvidenceRef] = None,
                         status_code: int = 0) -> EndpointRecord:
        """Register a disproven endpoint with reason and retest policy."""
        retest = self._get_retest_policy(reason)
        auth_behavior = AuthBehavior.REQUIRES_AUTH if reason == DisproveReason.AUTH_ENFORCED else \
                        AuthBehavior.AUTH_IRRELEVANT if reason == DisproveReason.SPA_FALLBACK else \
                        AuthBehavior.UNKNOWN

        reason_text = {
            DisproveReason.AUTH_ENFORCED: f"HTTP 401/403 — authentication enforced, access control working",
            DisproveReason.SPA_FALLBACK:  f"SPA shell (~75KB HTML) — client-side route, no server data",
            DisproveReason.NOT_FOUND:     f"HTTP 404 — endpoint does not exist",
            DisproveReason.EMPTY_RESPONSE: f"Response too small — no meaningful content",
            DisproveReason.SERVER_ERROR:  f"HTTP 5xx — server error, endpoint broken not vulnerable",
            DisproveReason.NO_RESPONSE:   f"Connection failed — endpoint unreachable",
        }.get(reason, reason.value)

        ep = EndpointRecord(
            url=url,
            outcome=ProbeOutcome.DISPROVEN,
            auth_behavior=auth_behavior,
            evidence=evidence,
            disprove_reason=reason,
            retest_policy=retest,
            classification_reason=reason_text,
            cycle_discovered=self.current_cycle,
            confidence=0.90,  # High confidence we know this is NOT vulnerable
            chain_candidate=False,
        )
        self.endpoints[url] = ep
        self.disproven_urls.add(url)
        self.budget_used += 1
        return ep

    def record_inconclusive(self, url: str,
                             evidence: Optional[EvidenceRef] = None,
                             reason: str = "HTTP 500 or ambiguous") -> EndpointRecord:
        """Register an inconclusive probe."""
        ep = EndpointRecord(
            url=url,
            outcome=ProbeOutcome.INCONCLUSIVE,
            auth_behavior=AuthBehavior.UNKNOWN,
            evidence=evidence,
            disprove_reason=None,
            retest_policy=RetestPolicy.AFTER_N_CYCLES,
            classification_reason=reason,
            cycle_discovered=self.current_cycle,
            confidence=0.30,
            chain_candidate=False,  # Cannot chain inconclusive
        )
        self.endpoints[url] = ep
        self.inconclusive_urls.add(url)
        self.inconclusive_counts[url] = self.inconclusive_counts.get(url, 0) + 1
        self.budget_used += 1
        return ep

    # ── Behavioral learning ───────────────────────────────────────────────────

    def learn_auth_behavior(self, namespace: str, behavior: AuthBehavior,
                             example_url: str):
        """Learn how a namespace handles authentication."""
        existing = [b for b in self.behaviors if b.namespace == namespace]
        if existing:
            existing[0].examples.append(example_url)
            existing[0].confidence = min(0.99, existing[0].confidence + 0.1)
        else:
            self.behaviors.append(LearnedBehavior(
                namespace=namespace,
                auth_pattern=behavior,
                url_pattern="",
                examples=[example_url],
                confidence=0.7,
                discovered_at=self.current_cycle,
            ))

    def learn_url_pattern(self, pattern: str, namespace: str,
                          example: str, confidence: float = 0.7):
        """Learn a URL pattern (e.g. 'capitalize resource names in /api/')."""
        existing = [b for b in self.behaviors
                    if b.namespace == namespace and b.url_pattern == pattern]
        if existing:
            existing[0].confidence = min(0.99, existing[0].confidence + 0.05)
            existing[0].examples.append(example)
        else:
            self.behaviors.append(LearnedBehavior(
                namespace=namespace,
                auth_pattern=AuthBehavior.UNKNOWN,
                url_pattern=pattern,
                examples=[example],
                confidence=confidence,
                discovered_at=self.current_cycle,
            ))

    def get_auth_expectation(self, url: str) -> AuthBehavior:
        """What do we expect for auth at this URL based on learned patterns?"""
        for behavior in sorted(self.behaviors,
                                key=lambda b: b.confidence, reverse=True):
            if behavior.namespace and behavior.namespace in url:
                return behavior.auth_pattern
        return AuthBehavior.UNKNOWN

    # ── Root cause grouping ───────────────────────────────────────────────────

    def _update_root_cause(self, url: str, evidence: EvidenceRef):
        """Group confirmed findings by root cause pattern."""
        # Infer pattern from evidence
        if evidence.sensitive_fields:
            pattern = "sensitive_data_exposure"
            category = "Sensitive Data Protection"
            severity = "HIGH"
        elif not evidence.auth_sent and evidence.status_code == 200:
            pattern = "unauthenticated_api"
            category = "Authorization / Access Control"
            severity = "HIGH"
        else:
            return

        # Find or create root cause
        for rc in self.root_causes:
            if rc.pattern == pattern and url not in rc.endpoints:
                rc.endpoints.append(url)
                rc.evidence_count += 1
                rc.verified = True
                return

        rc_id = f"RC-{len(self.root_causes)+1:03d}"
        self.root_causes.append(RootCause(
            root_id=rc_id,
            title=self._pattern_to_title(pattern),
            category=category,
            pattern=pattern,
            severity=severity,
            endpoints=[url],
            evidence_count=1,
            next_action=self._get_next_action(pattern),
            verified=True,
        ))

    def _pattern_to_title(self, pattern: str) -> str:
        return {
            "unauthenticated_api":   "Missing Authentication Enforcement",
            "unauthenticated_admin": "Unauthenticated Administrative Access",
            "no_rate_limiting":      "Missing Rate Limiting on Auth Endpoints",
            "dangerous_methods":     "Dangerous HTTP Methods Allowed",
            "sql_injection":         "SQL Injection Condition Detected",
            "sensitive_data_exposure": "Sensitive Data Exposure in API Response",
        }.get(pattern, f"Security Issue: {pattern}")

    def _get_next_action(self, pattern: str) -> str:
        return {
            "unauthenticated_api":   "Verify with authenticated session — same data returned?",
            "unauthenticated_admin": "Test admin functions with auth token for real impact scope",
            "no_rate_limiting":      "Send 10 rapid requests — verify no HTTP 429",
            "dangerous_methods":     "Test OPTIONS — confirm DELETE/PUT in Allow header",
            "sql_injection":         "Test Boolean: append AND 1=1 vs AND 1=2 — different responses?",
            "sensitive_data_exposure": "Document all sensitive fields returned without auth",
        }.get(pattern, "Manual review required")

    # ── Chain candidates ──────────────────────────────────────────────────────

    def _evaluate_chain_candidates(self):
        """Evaluate if confirmed findings can form attack chains."""
        confirmed_list = [
            self.endpoints[url]
            for url in self.confirmed_urls
            if url in self.endpoints
        ]

        if len(confirmed_list) < 2:
            return

        # Check for classic chains
        has_config = any("config" in ep.url.lower() for ep in confirmed_list)
        has_api    = any("/api/" in ep.url for ep in confirmed_list)
        has_admin  = any("admin" in ep.url.lower() for ep in confirmed_list)

        if has_config and has_api:
            self._add_chain_candidate(
                "Configuration + API Exposure",
                [ep.url for ep in confirmed_list
                 if "config" in ep.url.lower() or "/api/" in ep.url],
                "CRITICAL", 0.80,
            )

        if has_admin and has_api:
            self._add_chain_candidate(
                "Admin + API Access Chain",
                [ep.url for ep in confirmed_list
                 if "admin" in ep.url.lower() or "/api/" in ep.url],
                "CRITICAL", 0.75,
            )

    def _add_chain_candidate(self, title: str, endpoints: list[str],
                              severity: str, confidence: float):
        """Add or update a chain candidate."""
        for cc in self.chain_candidates:
            if cc.title == title:
                cc.confidence = max(cc.confidence, confidence)
                cc.evidence_count = len(endpoints)
                return
        self.chain_candidates.append(ChainCandidate(
            candidate_id=f"CC-{len(self.chain_candidates)+1:03d}",
            title=title,
            endpoints=endpoints,
            confidence=confidence,
            severity=severity,
            evidence_count=len(endpoints),
        ))

    # ── Stop conditions ───────────────────────────────────────────────────────

    def _check_stop_conditions(self):
        """Evaluate whether investigation should stop."""
        if self.budget_used >= self.budget_total:
            self.stop_triggered = True
            self.stop_condition = StopCondition.BUDGET_EXHAUSTED
            return

        # If we have 5+ confirmed findings with chain candidates — sufficient evidence
        if len(self.confirmed_urls) >= 5 and len(self.chain_candidates) >= 2:
            self.stop_condition = StopCondition.SUFFICIENT_EVIDENCE
            # Don't stop — but signal Queen

    def should_stop(self) -> tuple[bool, str]:
        """Should the investigation end?"""
        if self.stop_triggered:
            return True, f"Stop condition: {self.stop_condition.value if self.stop_condition else 'triggered'}"
        if self.budget_used >= int(self.budget_total * 0.9):
            return True, f"Budget nearly exhausted ({self.budget_used}/{self.budget_total})"
        return False, "Continue"

    # ── Queen coordination ────────────────────────────────────────────────────

    def queen_should_investigate(self, objective: str) -> tuple[bool, str]:
        """
        Queen checks if an objective is worth pursuing.
        Prevents Queen from repeating settled territory or generating invalid objectives.
        """
        obj_lower = objective.lower()

        # Hard blocks — these objective types are never valid
        BLOCKED_PATTERNS = [
            ("credential stuffing", "Credential stuffing requires confirmed rate limit absence"),
            ("brute force", "Brute force requires confirmed rate limit absence"),
            ("rapid credential", "Credential attacks require confirmed rate limit absence"),
            ("credential enumeration", "Credential enumeration requires confirmed rate limit absence"),
            ("credential harvest", "Credential harvesting is offensive — not in PROBE scope"),
            ("password spray", "Password spraying requires confirmed rate limit absence"),
            ("rate limit absence", "Rate limit absence objective — cannot exploit in PROBE mode"),
            ("version-specific", "Version endpoint speculation — not confirmed in JS discovery"),
            ("version specific", "Version endpoint speculation — not confirmed in JS discovery"),
            ("api version", "Version endpoint speculation — not confirmed in JS discovery"),
            ("v1/", "Version endpoint speculation — not confirmed in JS discovery"),
            ("v2/", "Version endpoint speculation — not confirmed in JS discovery"),
            ("v3/", "Version endpoint speculation — not confirmed in JS discovery"),
            ("/api/v1", "Version endpoint speculation — not confirmed in JS discovery"),
            ("/api/v2", "Version endpoint speculation — not confirmed in JS discovery"),
            ("/rest/v1", "Version endpoint speculation — not confirmed in JS discovery"),
            ("older api", "Version endpoint speculation — not confirmed in JS discovery"),
            ("legacy endpoint", "Version endpoint speculation — not confirmed in JS discovery"),
        ]
        for pattern, reason in BLOCKED_PATTERNS:
            if pattern in obj_lower:
                return False, f"BLOCKED: {reason}"

        # Don't investigate endpoints that were already refuted as SPA
        for url in self.disproven_urls:
            url_part = url.split("/")[-1].lower()
            ep = self.endpoints.get(url)
            if (ep and hasattr(ep, 'disprove_reason') and
                    ep.disprove_reason and 'SPA' in str(ep.disprove_reason) and
                    url_part and url_part in obj_lower):
                return False, f"BLOCKED: {url} was SPA — no server-side data"

        # Don't investigate confirmed territory
        for url in self.confirmed_urls:
            url_part = url.split("/")[-1].lower()
            if url_part and len(url_part) > 3 and url_part in obj_lower:
                return False, f"Already CONFIRMED: {url} — no need to reinvestigate"

        # Don't repeat completed objectives
        for completed in self.queen_objectives_completed:
            if self._objectives_similar(obj_lower, completed.lower()):
                return False, f"Similar objective already done: {completed[:60]}"

        return True, "New territory — proceed"

    def record_queen_objective(self, objective: str, success: bool):
        if success:
            self.queen_objectives_completed.append(objective[:120])
        else:
            self.queen_objectives_failed.append(objective[:120])

    def _objectives_similar(self, obj1: str, obj2: str) -> bool:
        skip = {"test", "exploit", "enumerate", "attempt", "analyze",
                "probe", "check", "verify", "confirm", "investigate"}
        def key_terms(obj: str) -> set:
            return {w for w in obj.split() if len(w) > 4 and w not in skip}
        t1, t2 = key_terms(obj1), key_terms(obj2)
        if not t1 or not t2:
            return False
        return len(t1 & t2) / max(len(t1), len(t2)) > 0.55

    # ── Confidence promotion context ──────────────────────────────────────────

    def get_confidence_context(self) -> dict:
        """
        Context for the scoring engine.
        More confirmed findings = higher ceiling for similar hypotheses.
        """
        return {
            "confirmed_count":    len(self.confirmed_urls),
            "disproven_count":    len(self.disproven_urls),
            "chain_candidates":   len(self.chain_candidates),
            "patterns_learned":   len([b for b in self.behaviors if b.url_pattern]),
            "auth_namespaces":    {b.namespace: b.auth_pattern.value
                                   for b in self.behaviors if b.auth_pattern != AuthBehavior.UNKNOWN},
        }

    # ── Context strings for agent prompts ─────────────────────────────────────

    def get_alpha_context(self) -> str:
        """
        Injected into every Alpha reasoning prompt.
        Alpha reads this and knows exactly what's settled.
        """
        lines = []

        if self.confirmed_urls:
            lines.append(f"CONFIRMED VULNERABLE — DO NOT REPROBE ({len(self.confirmed_urls)}):")
            for url in list(self.confirmed_urls)[-6:]:
                ep = self.endpoints.get(url)
                lines.append(f"  ✅ {url}")
                if ep:
                    lines.append(f"     Evidence: {ep.classification_reason[:80]}")
                    lines.append(f"     Retest: {ep.retest_policy.value}")

        if self.disproven_urls:
            lines.append(f"\nDISPROVEN — DO NOT REPROBE ({len(self.disproven_urls)}):")
            for url in list(self.disproven_urls)[-10:]:
                ep = self.endpoints.get(url)
                reason = ep.disprove_reason.value if ep and ep.disprove_reason else "disproven"
                lines.append(f"  ❌ {url} ({reason})")

        if self.inconclusive_urls:
            lines.append(f"\nINCONCLUSIVE ({len(self.inconclusive_urls)}) — retry with new angle only:")
            for url in list(self.inconclusive_urls)[-5:]:
                lines.append(f"  🔍 {url}")

        auth_known = {b.namespace: b.auth_pattern.value
                      for b in self.behaviors
                      if b.auth_pattern != AuthBehavior.UNKNOWN and b.namespace}
        if auth_known:
            lines.append(f"\nLEARNED AUTH BEHAVIOR:")
            for ns, behavior in auth_known.items():
                lines.append(f"  {ns} → {behavior}")

        patterns = [b for b in self.behaviors if b.url_pattern]
        if patterns:
            lines.append(f"\nLEARNED URL PATTERNS:")
            for p in patterns[-4:]:
                lines.append(f"  • {p.url_pattern} (confidence: {p.confidence:.0%})")

        stop, reason = self.should_stop()
        if stop:
            lines.append(f"\n⛔ STOP CONDITION: {reason}")

        budget_pct = self.budget_used / self.budget_total
        lines.append(f"\nBudget: {self.budget_used}/{self.budget_total} ({budget_pct:.0%} used)")

        return "\n".join(lines) if lines else "No prior intelligence — first cycle"

    def get_queen_context(self) -> str:
        """Injected into every Queen strategic review."""
        lines = [
            f"Session: {self.budget_used}/{self.budget_total} requests used",
            f"Confirmed: {len(self.confirmed_urls)} | "
            f"Disproven: {len(self.disproven_urls)} | "
            f"Inconclusive: {len(self.inconclusive_urls)}",
        ]

        if self.confirmed_urls:
            lines.append(f"\nCONFIRMED (do not reinvestigate):")
            for url in self.confirmed_urls:
                lines.append(f"  ✅ {url}")

        if self.queen_objectives_completed:
            lines.append(f"\nCOMPLETED OBJECTIVES (do not repeat):")
            for obj in self.queen_objectives_completed[-6:]:
                lines.append(f"  ✓ {obj[:90]}")

        if self.root_causes:
            lines.append(f"\nROOT CAUSES IDENTIFIED:")
            for rc in self.root_causes:
                lines.append(f"  [{rc.severity}] {rc.title}: {len(rc.endpoints)} endpoints confirmed")

        if self.chain_candidates:
            lines.append(f"\nCHAIN CANDIDATES (CONFIRMED endpoints only):")
            for cc in self.chain_candidates:
                lines.append(f"  {cc.title} ({cc.confidence:.0%} confidence)")

        stop, reason = self.should_stop()
        if stop:
            lines.append(f"\n⛔ STOP CONDITION: {reason}")
        elif self.stop_condition == StopCondition.SUFFICIENT_EVIDENCE:
            lines.append(f"\n✅ Sufficient evidence gathered — consider concluding")

        lines.append(f"\nWasted probes prevented: {self.probes_prevented}")

        return "\n".join(lines)

    # ── Retest policy ─────────────────────────────────────────────────────────

    def _get_retest_policy(self, reason: DisproveReason) -> RetestPolicy:
        return {
            DisproveReason.AUTH_ENFORCED:  RetestPolicy.IF_AUTH_ADDED,
            DisproveReason.SPA_FALLBACK:   RetestPolicy.ALWAYS_SKIP,
            DisproveReason.NOT_FOUND:      RetestPolicy.NEVER,
            DisproveReason.EMPTY_RESPONSE: RetestPolicy.AFTER_N_CYCLES,
            DisproveReason.SERVER_ERROR:   RetestPolicy.AFTER_N_CYCLES,
            DisproveReason.NO_RESPONSE:    RetestPolicy.AFTER_N_CYCLES,
        }.get(reason, RetestPolicy.NEVER)

    # ── Summary ───────────────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        return {
            "session_id":            self.session_id,
            "total_requests":        self.budget_used,
            "budget_remaining":      self.budget_total - self.budget_used,
            "confirmed":             len(self.confirmed_urls),
            "disproven":             len(self.disproven_urls),
            "inconclusive":          len(self.inconclusive_urls),
            "root_causes":           len(self.root_causes),
            "chain_candidates":      len(self.chain_candidates),
            "behaviors_learned":     len(self.behaviors),
            "probes_prevented":      self.probes_prevented,
            "queen_objectives_done": len(self.queen_objectives_completed),
            "stop_condition":        self.stop_condition.value if self.stop_condition else None,
            "confidence_context":    self.get_confidence_context(),
        }
