# AI Agent Governance MVP

Observability and governance for AI support agents. The core problem it
solves: an agent can look healthy on normal operational metrics (resolution
rate, response time, volume) while silently drifting on the high-risk case
categories that actually matter — billing disputes, fraud claims,
policy-sensitive issues. This system detects that drift per category,
raises alerts, and trips an automatic rollback gate before the drift causes
damage.

## How it works

1. **Ingest** — agent decisions enter via the REST API (or the constrained-
   decoding parser for raw LLM output) and are validated, categorized, and
   stored in SQLite.
2. **Detect** — a background scheduler compares each category's recent
   window against its baseline window using effect sizes (Cohen's h/d) and
   significance tests, producing a composite drift score per category.
3. **Govern** — drift scores are checked against per-category thresholds
   from `config/governance.yaml`; violations raise alerts, and rollback
   rules can trigger an automatic rollback event.
4. **Observe** — a PM-facing terminal dashboard, a self-contained HTML
   report, JSON APIs, Prometheus metrics, and an SSE event stream all answer
   the same question through one shared status derivation: *is the agent
   safe to continue?*

## Quick start

```bash
cd ai-governance-mvp
pip install -r requirements.txt

# Run the test suite (unit + behavioral layers, coverage gate at 90%)
python -m pytest

# Seed demo data and render the terminal dashboard
python demo.py

# Start the API server (config, DB path, port are all overridable)
python serve.py --config config/governance.yaml --port 8000
```

Then open `http://localhost:8000/docs` for the interactive API docs, or
`http://localhost:8000/governance/report/html` for the PM-facing report.

## Key endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /decisions`, `POST /decisions/batch` | Ingest agent decisions |
| `GET /governance/report` | Full detection pass + JSON report |
| `GET /governance/report/html` | Self-contained HTML report for PMs |
| `GET /governance/status` | Lightweight health probe |
| `GET /governance/alerts` | Active (or all) drift alerts |
| `POST /governance/preflight` | Pre-deployment batch validation |
| `GET /governance/versions` | Per-agent-version behavior comparison |
| `GET /governance/events/stream` | SSE stream of governance events |
| `GET /prometheus/metrics` | Prometheus text-format metrics |

## CI/CD gate

`ci_gate.py` blocks deployments whose candidate decisions violate governance
thresholds:

```bash
python ci_gate.py --decisions candidate_decisions.json \
                  --config config/governance.yaml \
                  --agent-version v2.1 --fail-on-warning
```

Exit codes: `0` safe to deploy, `1` blocked, `2` warning (advisory), `3`
usage/config error. `GOVERNANCE_DETECTION_WINDOW` and
`GOVERNANCE_MAX_ERROR_RATE` override the loaded thresholds for every
category, high-risk categories included.

## Configuration

`config/governance.yaml` defines the detection windows (time-anchored by
default; count-based as a fallback mode), per-category drift thresholds and
weights, categorization patterns, and rollback rules. Both `serve.py` and
`ci_gate.py --config` consume the same file, so the server and the
deployment gate enforce identical thresholds. Set thresholds *before* the
agent goes to production — retuning them after the fact undermines the
governance guarantee.

## Layout

```
src/governance/   schemas, config, shared status derivation,
                  constrained decoding (outlines → instructor → parser),
                  pre-flight validation
src/ingestion/    validation, categorization, SQLite store
src/detection/    per-category drift detection and statistics
src/engine/       alerts, rollback gate, scheduler, webhooks, SSE broker
src/api/          FastAPI app, models, HTML report
src/dashboard/    Rich-based terminal dashboard
tests/            two layers: unit tests + behavioral drift tests
                  (`-m behavioral`) whose failures act as a rollback gate
```

This project shares a repository with the `veriscan` artifact-verification
tool but is fully independent of it.
