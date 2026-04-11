"""
sentinel/core/policy.py

Policy Enforcement Layer — delegates to validator.py (THE authoritative safety layer).

ARCHITECTURE NOTE:
  validator.py is the single source of truth for what actions are permitted.
  This module exists as a thin compatibility shim and for rate-limit tracking.

  Do NOT add new enforcement logic here. Add it to validator.py.
  Two enforcement layers that can drift is worse than one consistent layer.

  policy.py is retained for:
    - Per-endpoint request counting (rate limiting)
    - Payload-class semantic labelling (context for validators, not enforcement)
    - Future: per-scan budget tracking
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class PolicyViolation(Exception):
    """Raised when a rate limit or budget is exceeded."""
    pass


class PolicyProfile(str, Enum):
    PASSIVE = "PASSIVE"
    PROBE   = "PROBE"
    ACTIVE  = "ACTIVE"
    AUDIT   = "AUDIT"


@dataclass
class PolicyGate:
    """
    Rate-limit and budget tracker.
    Enforcement (what's blocked) lives in validator.py.
    This tracks counts only.
    """
    profile:              PolicyProfile
    max_requests_total:   int
    max_requests_per_ep:  int
    request_count:        dict = field(default_factory=dict)
    total_requests:       int = 0

    def check_rate_limit(self, target: str) -> bool:
        """
        Check and increment request counters.
        Raises PolicyViolation only if a rate limit is exceeded.
        All action-type enforcement is handled by validator.validate_action().
        """
        ep_count = self.request_count.get(target, 0)
        if ep_count >= self.max_requests_per_ep:
            raise PolicyViolation(
                f"Rate limit: max {self.max_requests_per_ep} requests per endpoint reached for {target}."
            )
        if self.total_requests >= self.max_requests_total:
            raise PolicyViolation(
                f"Budget exhausted: {self.max_requests_total} total requests reached."
            )
        self.request_count[target] = ep_count + 1
        self.total_requests += 1
        return True

    def record_request(self, target: str):
        """Record a request without blocking."""
        self.request_count[target] = self.request_count.get(target, 0) + 1
        self.total_requests += 1

    def get_stats(self) -> dict:
        return {
            "profile":          self.profile.value,
            "total_requests":   self.total_requests,
            "max_requests":     self.max_requests_total,
            "endpoints_probed": len(self.request_count),
            "budget_remaining": self.max_requests_total - self.total_requests,
        }


def get_policy(profile: PolicyProfile) -> PolicyGate:
    """Get a rate-limit gate for a scan profile."""
    limits = {
        PolicyProfile.PASSIVE: (50,  2),
        PolicyProfile.PROBE:   (300, 5),
        PolicyProfile.ACTIVE:  (1000, 10),
        PolicyProfile.AUDIT:   (400,  5),
    }
    total, per_ep = limits.get(profile, (300, 5))
    return PolicyGate(
        profile=profile,
        max_requests_total=total,
        max_requests_per_ep=per_ep,
    )


def policy_check_probe(url: str, method: str, policy: PolicyGate,
                       payload_class: str = "observation") -> bool:
    """
    Check rate limits before a probe.
    Action-type enforcement (blocked methods, modes) is in validator.validate_action().
    Call both: validate_action() for what's allowed, this for how many times.
    """
    try:
        return policy.check_rate_limit(url)
    except PolicyViolation as e:
        print(f"[POLICY] Rate limit: {e}")
        return False
