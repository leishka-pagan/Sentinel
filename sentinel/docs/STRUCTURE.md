# Sentinel — Project Structure

```
sentinel/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── run_scan.py              ← Quick CLI runner (no Flask needed)
│
├── sentinel/
│   ├── __init__.py
│   │
│   ├── core/               ← Shared models, safety layer, audit log
│   │   ├── __init__.py
│   │   ├── models.py        ← ScanSession, Finding, ScanResult, enums
│   │   ├── validator.py     ← validate_action() — THE safety gate
│   │   └── audit.py         ← Append-only audit log (local + Cosmos)
│   │
│   ├── agents/             ← All AI agents
│   │   ├── __init__.py
│   │   ├── orchestrator.py  ← Claude-powered main brain
│   │   ├── sast_agent.py    ← Static analysis (Bandit + TruffleHog)
│   │   ├── deps_agent.py    ← Dependency CVE scanning (pip-audit)
│   │   ├── reporter.py      ← JSON + Markdown report generation
│   │   │
│   │   │   [Phase 2]
│   │   ├── config_agent.py  ← Misconfiguration detection (coming)
│   │   │
│   │   │   [Phase 3]
│   │   └── recon_agent.py   ← Passive recon (coming)
│   │
│   ├── api/                ← Flask REST API
│   │   ├── __init__.py
│   │   └── app.py           ← Endpoints: /sessions, /scans, /audit
│   │
│   ├── tools/              ← Tool wrappers (Phase 2+)
│   │
│   └── tests/
│       └── test_validator.py ← Safety layer tests (run these first)
│
├── logs/                   ← Audit logs (gitignored, created at runtime)
└── reports/                ← Scan reports (gitignored, created at runtime)
```

## Key Safety Files

| File | Purpose |
|---|---|
| `core/validator.py` | Every agent action passes through here |
| `core/audit.py` | Immutable record of every action |
| `core/models.py` | Mode permissions defined here |
| `tests/test_validator.py` | Verify safety layer works before anything else |

## Flow

```
run_scan.py or API
    → ScanSession created (approved=False)
    → User confirms authorization (approved=True)
    → ACTIVE mode: second confirmation required
    → Orchestrator plans which agents to run
    → Each agent calls validate_action() before any tool
    → validate_action() checks: session approved? mode allows it? target in scope? not hardcoded blocked?
    → Findings aggregated → Report generated → Audit logged
```
