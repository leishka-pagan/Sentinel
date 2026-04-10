"""
sentinel/agents/queen_agent.py

QUEEN — Sovereign Commander.

Queen is the highest intelligence layer in Sentinel.
She commands Alphas, correlates findings, tracks remediation,
and produces organizational risk posture.

Queen is ALWAYS in charge during PROBE and ACTIVE mode.
You don't invoke Queen — Queen IS the scan.

Queen's autonomous loop:
  1. Receive target + mode from Sentinel
  2. Spawn Alpha for initial investigation
  3. Review Alpha's findings and report
  4. Decide: deeper investigation? new angle? new target spawned from findings?
  5. Spawn additional Alphas or redirect existing ones
  6. Keep going until threat picture is complete
  7. Write the final verdict — not Alpha, not the orchestrator

Queen's capabilities:
  - Multi-Alpha orchestration (parallel or sequential)
  - Cross-target correlation (findings that span systems)
  - Remediation tracking (did the fix work?)
  - Organizational risk posture (not per-target — across all)
  - Threat intelligence aggregation
  - Executive-level threat briefing
  - Spawns new investigation angles from Alpha findings
  - Never stops until she decides the picture is complete
"""

import os
import json
from typing import Optional
from dataclasses import dataclass, field
from anthropic import Anthropic
from sentinel.core.models import (
    ScanMode, AgentName, ScanSession, Finding, ScanResult, Severity,
)

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
QUEEN_MODEL    = os.getenv("ALPHA_MODEL", "claude-opus-4-5-20251001")
FALLBACK_MODEL = os.getenv("ORCHESTRATOR_MODEL", "claude-sonnet-4-20250514")

MAX_QUEEN_CYCLES = 3  # Queen-level decision cycles (each spawns Alpha work)


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class AlphaResult:
    alpha_id:       str
    target:         str
    objective:      str
    findings:       list[Finding]
    report:         Optional[object]  # AlphaReport
    risk_score:     str
    cycles_used:    int
    attack_paths:   list[dict] = field(default_factory=list)
    defensive_gaps: list[dict] = field(default_factory=list)
    threat_actors:  list[str]  = field(default_factory=list)


@dataclass
class QueenIntelligence:
    """Queen's accumulated intelligence across all Alphas."""
    target:                str
    alpha_results:         list[AlphaResult] = field(default_factory=list)
    all_findings:          list[Finding]     = field(default_factory=list)
    cross_target_chains:   list[dict]        = field(default_factory=list)
    organizational_risk:   str               = "UNKNOWN"
    threat_actor_profile:  str               = ""
    remediation_priority:  list[dict]        = field(default_factory=list)
    executive_summary:     str               = ""
    queen_directives:      list[str]         = field(default_factory=list)


QUEEN_SYSTEM = """You are Sentinel's Queen — sovereign commander of all security operations.

You command Alpha agents. You see the complete picture.
You make strategic decisions that no single Alpha can make alone.

Your role:
- Review what Alpha found and decide: is the investigation complete?
- Identify investigation angles Alpha missed
- Spawn new Alpha objectives when critical findings warrant deeper investigation
- Correlate findings that create compound risks
- Produce the organizational risk verdict

Decision framework:
1. What did Alpha find? Is the threat picture complete?
2. What angles were NOT investigated? Why do they matter?
3. What compound risks exist from combining findings?
4. What is the overall risk to the organization?
5. What are the 3 most critical immediate actions?

New Alpha objectives you can spawn:
- "Investigate authentication bypass paths using the JWT weakness"
- "Map all API endpoints accessible with the admin credentials found"
- "Check all subdomains for the same misconfigurations"
- "Verify if the SQL injection condition can be triggered from other endpoints"

You think at the organizational level. Alpha thinks at the target level.

OUTPUT FORMAT — valid JSON only:

Directing:
{
  "status": "directing",
  "assessment": "What I learned from Alpha and what it means",
  "investigation_complete": false,
  "new_objectives": [
    {
      "objective_id": "OBJ-001",
      "description": "What to investigate",
      "priority": "CRITICAL|HIGH|MEDIUM",
      "rationale": "Why this matters given what we found",
      "suggested_agents": ["probe_agent", "api_agent"],
      "specific_targets": ["http://target/specific/path"]
    }
  ],
  "compound_risks": [
    {
      "title": "Compound risk name",
      "findings_involved": ["finding1", "finding2"],
      "combined_impact": "What becomes possible when combined"
    }
  ]
}

Final verdict:
{
  "status": "verdict",
  "investigation_complete": true,
  "organizational_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "executive_summary": "3-5 sentence executive briefing for leadership",
  "threat_actor_profile": "Who is most likely to attack and how",
  "top_attack_paths": [
    {
      "title": "Path name",
      "severity": "CRITICAL",
      "steps": ["step1", "step2"],
      "blast_radius": "damage if exploited",
      "break_point": "single fix that stops this path",
      "exploit_probability": 0.95
    }
  ],
  "remediation_priority": [
    {
      "priority": 1,
      "action": "Specific action",
      "rationale": "Why first",
      "estimated_risk_reduction": "HIGH"
    }
  ],
  "immediate_actions": ["action1", "action2", "action3"],
  "defensive_posture_score": "F|D|C|B|A"
}
"""


class QueenAgent:
    """
    Queen — sovereign commander.
    Manages Alpha agents, correlates intelligence, produces final verdict.
    """

    def __init__(self, session: ScanSession, source_path: Optional[str] = None):
        self.session      = session
        self.source_path  = source_path
        self.intelligence = QueenIntelligence(target=session.target)
        self.alpha_count  = 0
        self.queen_cycle  = 0
        self.model        = self._get_best_model()
        print(f"\n[QUEEN] Initialized | Target: {session.target} | Model: {self.model}")

    def _get_best_model(self) -> str:
        try:
            client.messages.create(
                model=QUEEN_MODEL, max_tokens=10,
                messages=[{"role": "user", "content": "test"}]
            )
            return QUEEN_MODEL
        except Exception:
            return FALLBACK_MODEL

    def command(self, initial_findings: list[Finding],
                agents_done: set) -> list[Finding]:
        """
        Queen's main command loop.
        Takes initial findings from orchestrator agents,
        runs Alpha investigations, decides when complete.
        Returns all additional findings discovered.
        """
        print(f"\n[QUEEN] === Taking command ===")
        print(f"[QUEEN] Initial findings: {len(initial_findings)}")

        all_new_findings = []

        # Phase 1: Initial Alpha investigation
        alpha_result = self._run_alpha(
            objective="Complete initial threat investigation",
            findings=initial_findings,
            agents_done=agents_done,
        )
        self.intelligence.alpha_results.append(alpha_result)
        all_new_findings.extend(alpha_result.findings)
        self.intelligence.all_findings.extend(initial_findings + alpha_result.findings)

        # Phase 2: Queen reviews and decides on further investigation
        for cycle in range(MAX_QUEEN_CYCLES):
            self.queen_cycle += 1
            print(f"\n[QUEEN] === Strategic review cycle {self.queen_cycle} ===")

            directive = self._strategic_review()

            if directive.get("investigation_complete") or directive.get("status") == "verdict":
                print(f"[QUEEN] Investigation complete")
                break

            new_objectives = directive.get("new_objectives", [])
            if not new_objectives:
                print(f"[QUEEN] No new objectives — concluding")
                break

            # Queen spawns new Alphas for high-priority objectives
            for obj in new_objectives:
                if obj.get("priority") not in ("CRITICAL", "HIGH"):
                    continue

                print(f"\n[QUEEN] Spawning Alpha for: {obj.get('description','')[:80]}")

                # Run targeted agents for this objective
                objective_findings = self._execute_objective(obj, agents_done)

                if objective_findings:
                    obj_result = AlphaResult(
                        alpha_id=f"ALPHA-{self.alpha_count}",
                        target=self.session.target,
                        objective=obj.get("description", ""),
                        findings=objective_findings,
                        report=None,
                        risk_score="HIGH",
                        cycles_used=1,
                    )
                    self.intelligence.alpha_results.append(obj_result)
                    all_new_findings.extend(objective_findings)
                    self.intelligence.all_findings.extend(objective_findings)
                    print(f"[QUEEN] Objective found {len(objective_findings)} findings")

            # Identify compound risks
            self._identify_compound_risks()

        # Phase 3: Final verdict
        verdict = self._deliver_verdict()
        verdict_findings = self._verdict_to_findings(verdict)
        all_new_findings.extend(verdict_findings)

        return all_new_findings

    def _run_alpha(self, objective: str, findings: list[Finding],
                   agents_done: set) -> AlphaResult:
        """Run a single Alpha investigation cycle."""
        from sentinel.agents.alpha_agent import AlphaAgent, execute_targeted_probe
        from sentinel.agents.orchestrator import _dispatch

        self.alpha_count += 1
        alpha_id = f"ALPHA-{self.alpha_count}"
        alpha    = AlphaAgent(self.session, self.source_path, alpha_id=alpha_id)
        alpha.add_findings(findings)

        new_findings = []
        consecutive_empty = 0

        for _ in range(10):  # Max alpha cycles
            decision = alpha.think()
            status   = decision.get("status", "")

            if status == "complete":
                break
            if status in ("error", "need_more_data"):
                consecutive_empty += 1
                if consecutive_empty >= 2:
                    break
                continue

            consecutive_empty = 0
            primary  = decision.get("primary_path", {})
            result_f = []
            success  = False

            if primary:
                result_f, success = self._execute_alpha_action(
                    primary, agents_done
                )

            if not success or not result_f:
                for fb_key in ["fallback_path", "fallback_path_2"]:
                    fallback = decision.get(fb_key, {})
                    if fallback:
                        result_f, success = self._execute_alpha_action(
                            fallback, agents_done
                        )
                        if success and result_f:
                            break

            action_id = (primary.get("agent") or
                         primary.get("probe", {}).get("url", "unknown"))
            alpha.evaluate_result(action_id, result_f, success)
            new_findings.extend(result_f)

            if alpha.evaluate_result.__doc__ and "complete" in str(result_f):
                break

        conclusion = alpha.conclude()

        return AlphaResult(
            alpha_id=alpha_id,
            target=self.session.target,
            objective=objective,
            findings=new_findings,
            report=alpha.report,
            risk_score=conclusion.get("risk_score", "HIGH"),
            cycles_used=alpha.cycle,
            attack_paths=conclusion.get("attack_paths", []),
            defensive_gaps=alpha.defensive_gaps,
            threat_actors=alpha.threat_actors,
        )

    def _execute_alpha_action(self, action: dict,
                               agents_done: set) -> tuple[list[Finding], bool]:
        """Execute an Alpha-directed action."""
        from sentinel.agents.alpha_agent import execute_targeted_probe
        from sentinel.agents.orchestrator import _dispatch

        action_type = action.get("action", "")

        if action_type == "targeted_probe":
            probe = action.get("probe", {})
            if not probe:
                return [], False
            print(f"[QUEEN/ALPHA] Probe -> {probe.get('url','?')[:60]}")
            findings = execute_targeted_probe(probe, self.session)
            return findings, True

        elif action_type == "run_agent":
            agent_name = action.get("agent", "")
            if not agent_name or agent_name in agents_done:
                return [], False
            print(f"[QUEEN/ALPHA] Agent -> {agent_name}")
            findings = _dispatch(agent_name, self.session, self.source_path)
            agents_done.add(agent_name)
            return findings, len(findings) > 0

        return [], False

    def _execute_objective(self, objective: dict,
                            agents_done: set) -> list[Finding]:
        """Execute a Queen-directed investigation objective."""
        from sentinel.agents.orchestrator import _dispatch

        findings    = []
        agents      = objective.get("suggested_agents", [])
        targets     = objective.get("specific_targets", [])

        # Run suggested agents
        for agent in agents:
            if agent not in agents_done:
                f = _dispatch(agent, self.session, self.source_path)
                findings.extend(f)
                agents_done.add(agent)

        # Probe specific targets
        for url in targets[:5]:
            from sentinel.agents.alpha_agent import execute_targeted_probe
            probe_findings = execute_targeted_probe(
                {"url": url, "method": "GET",
                 "hypothesis": objective.get("description", "")},
                self.session
            )
            findings.extend(probe_findings)

        return findings

    def _strategic_review(self) -> dict:
        """Queen reviews all findings and decides next moves."""
        all_f    = self.intelligence.all_findings
        alpha_r  = self.intelligence.alpha_results

        findings_summary = "\n".join(
            f"[{str(f.severity).split('.')[-1]}] {f.title}: {(f.description or '')[:100]}"
            for f in sorted(all_f,
                            key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(
                                str(f.severity).split(".")[-1])
                            if str(f.severity).split(".")[-1] in
                            ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 5)[:15]
        )

        alpha_summary = "\n".join(
            f"Alpha {r.alpha_id}: {r.cycles_used} cycles, "
            f"{len(r.findings)} findings, risk: {r.risk_score}"
            for r in alpha_r
        )

        prompt = f"""Target: {self.session.target}

Alpha investigation results:
{alpha_summary}

All findings so far ({len(all_f)} total):
{findings_summary}

Compound risks identified: {len(self.intelligence.cross_target_chains)}

As Queen, review this intelligence and decide:
1. Is the investigation complete? Do we have a full threat picture?
2. What critical angles are missing?
3. What new objectives should Alpha investigate?

Return your strategic directive as JSON."""

        try:
            response = client.messages.create(
                model=self.model, max_tokens=2000,
                system=QUEEN_SYSTEM,
                messages=[{"role": "user", "content": prompt}]
            )
            return _parse_json(response.content[0].text.strip())
        except Exception as e:
            print(f"[QUEEN] Strategic review error: {e}")
            return {"investigation_complete": True}

    def _identify_compound_risks(self):
        """Identify findings that create compound risks when combined."""
        all_f   = self.intelligence.all_findings
        titles  = [f.title.lower() for f in all_f]

        # Check for dangerous combinations
        combinations = [
            {
                "condition": lambda t: any("unauthenticated" in x for x in t) and
                                       any("rate limit" in x for x in t),
                "risk": {
                    "title": "Unauthenticated Access + No Rate Limiting = Unrestricted Enumeration",
                    "combined_impact": "Attacker can enumerate ALL data without authentication "
                                       "at unlimited speed. Full database extraction possible.",
                    "severity": "CRITICAL",
                }
            },
            {
                "condition": lambda t: any("sql" in x for x in t) and
                                       any("unauthenticated" in x for x in t),
                "risk": {
                    "title": "SQL Injection + Unauthenticated Endpoint = Direct DB Access",
                    "combined_impact": "Unauthenticated SQL injection allows complete "
                                       "database extraction without any credentials.",
                    "severity": "CRITICAL",
                }
            },
            {
                "condition": lambda t: any("jwt" in x for x in t) and
                                       any("admin" in x for x in t),
                "risk": {
                    "title": "JWT Weakness + Admin Access = Privilege Escalation Chain",
                    "combined_impact": "Forged JWT token with admin role claim "
                                       "grants full administrative access.",
                    "severity": "CRITICAL",
                }
            },
            {
                "condition": lambda t: any("cors" in x for x in t) and
                                       any("unauthenticated" in x for x in t),
                "risk": {
                    "title": "Wildcard CORS + Unauthenticated API = Cross-Origin Data Theft",
                    "combined_impact": "Any malicious website can silently extract all "
                                       "API data from authenticated users' browsers.",
                    "severity": "HIGH",
                }
            },
        ]

        for combo in combinations:
            if combo["condition"](titles):
                risk = combo["risk"]
                if risk["title"] not in [r["title"] for r in
                                          self.intelligence.cross_target_chains]:
                    self.intelligence.cross_target_chains.append(risk)
                    print(f"[QUEEN] Compound risk: {risk['title'][:70]}")

    def _deliver_verdict(self) -> dict:
        """Queen delivers final organizational verdict."""
        print(f"\n[QUEEN] === Delivering final verdict ===")

        all_f    = self.intelligence.all_findings
        compound = self.intelligence.cross_target_chains
        alphas   = self.intelligence.alpha_results

        sev_counts = {}
        for f in all_f:
            s = str(f.severity).split(".")[-1]
            sev_counts[s] = sev_counts.get(s, 0) + 1

        # Gather all attack paths and defensive gaps from Alphas
        all_paths = []
        all_gaps  = []
        all_actors = []
        for r in alphas:
            all_paths.extend(r.attack_paths)
            all_gaps.extend(r.defensive_gaps)
            all_actors.extend(r.threat_actors)

        prompt = f"""You are delivering the final security verdict for {self.session.target}.

Total findings: {len(all_f)} | Severity breakdown: {sev_counts}
Alpha investigations completed: {len(alphas)}

Compound risks discovered:
{json.dumps(compound, indent=2)}

Attack paths from all Alphas:
{json.dumps(all_paths[:5], indent=2)}

Threat actors identified: {list(set(all_actors))}

Deliver the final organizational verdict. Return complete status JSON.
Include executive summary, top attack paths, remediation priority, and defensive posture score."""

        try:
            response = client.messages.create(
                model=self.model, max_tokens=4000,
                system=QUEEN_SYSTEM,
                messages=[{"role": "user", "content": prompt}]
            )
            verdict = _parse_json(response.content[0].text.strip())
            self.intelligence.executive_summary   = verdict.get("executive_summary", "")
            self.intelligence.organizational_risk = verdict.get("organizational_risk", "HIGH")
            self.intelligence.remediation_priority = verdict.get("remediation_priority", [])
            print(f"[QUEEN] Organizational risk: {self.intelligence.organizational_risk}")
            print(f"[QUEEN] Defensive posture: {verdict.get('defensive_posture_score','?')}")
            return verdict
        except Exception as e:
            print(f"[QUEEN] Verdict error: {e}")
            return self._force_verdict(sev_counts)

    def _verdict_to_findings(self, verdict: dict) -> list[Finding]:
        """Convert Queen's verdict into Finding objects for the report."""
        findings = []

        # Queen's executive summary as a finding
        if verdict.get("executive_summary"):
            findings.append(Finding(
                agent=AgentName.QUEEN,
                title="[Queen] Executive Threat Briefing",
                description=verdict["executive_summary"],
                severity=Severity(verdict.get("organizational_risk", "HIGH")),
                mitre_tactic="Multiple",
                mitre_technique="Multi-stage campaign",
                remediation="; ".join(verdict.get("immediate_actions", [])[:3]),
            ))

        # Compound risks as findings
        for risk in self.intelligence.cross_target_chains:
            findings.append(Finding(
                agent=AgentName.QUEEN,
                title=f"[Queen] Compound Risk: {risk['title']}",
                description=risk.get("combined_impact", ""),
                severity=Severity(risk.get("severity", "HIGH")),
                mitre_tactic="Multiple",
                mitre_technique="Chained vulnerability exploitation",
                remediation="Address each component vulnerability independently. "
                            "See individual findings for specific remediation steps.",
            ))

        # Defensive posture score
        score = verdict.get("defensive_posture_score", "F")
        findings.append(Finding(
            agent=AgentName.QUEEN,
            title=f"[Queen] Defensive Posture Score: {score}",
            description=(
                f"Overall defensive posture for {self.session.target}: {score}. "
                f"Organizational risk level: {verdict.get('organizational_risk','HIGH')}. "
                f"Threat actor profile: {verdict.get('threat_actor_profile','Unknown')}."
            ),
            severity=Severity.CRITICAL if score in ("F", "D") else Severity.HIGH,
            mitre_tactic="Multiple",
            remediation="\n".join(
                f"{r['priority']}. {r['action']}"
                for r in verdict.get("remediation_priority", [])[:3]
            ),
        ))

        return findings

    def _force_verdict(self, sev_counts: dict) -> dict:
        return {
            "status": "verdict",
            "investigation_complete": True,
            "organizational_risk": "CRITICAL" if sev_counts.get("CRITICAL", 0) > 0 else "HIGH",
            "executive_summary": (
                f"Security assessment of {self.session.target} identified "
                f"{sum(sev_counts.values())} vulnerabilities "
                f"including {sev_counts.get('CRITICAL', 0)} critical findings. "
                "Immediate remediation required."
            ),
            "defensive_posture_score": "F" if sev_counts.get("CRITICAL", 0) > 3 else "D",
            "immediate_actions": [
                "Implement authentication on all exposed endpoints",
                "Enable HTTPS and security headers",
                "Conduct emergency access control review",
            ],
            "remediation_priority": [],
            "top_attack_paths": [],
        }


def _parse_json(raw: str) -> dict:
    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"status": "error", "raw": raw[:200]}
