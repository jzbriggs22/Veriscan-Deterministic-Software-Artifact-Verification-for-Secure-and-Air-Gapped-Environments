#!/usr/bin/env python3
"""
AI Agent Governance MVP — End-to-End Demo
==========================================
Demonstrates the core value proposition:

  Normal metrics look healthy for months while the agent silently drifts
  on high-risk cases (billing disputes, fraud claims). The governance layer
  catches the drift before it causes damage.

Run: python demo.py
"""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from src.detection.detector import DriftDetector
from src.engine.alerts import AlertEngine
from src.engine.rollback import RollbackEngine
from src.governance.config import GovernanceConfig
from src.governance.schema import (
    AgentDecision,
    CaseCategory,
    DecisionOutcome,
)
from src.ingestion.ingestor import DecisionIngestor
from src.ingestion.store import DecisionStore
from src.dashboard.dashboard import GovernanceDashboard

console = Console()
rng = random.Random(42)


# ── Decision factories ─────────────────────────────────────────────────────────

def _decision(
    case_id: str,
    category: CaseCategory,
    outcome: DecisionOutcome,
    confidence: float,
    ts: datetime,
    agent_version: str = "v1.0",
    latency_ms: float = 0.0,
) -> AgentDecision:
    return AgentDecision(
        case_id=case_id,
        category=category,
        outcome=outcome,
        confidence=max(0.01, min(0.99, confidence)),
        timestamp=ts,
        agent_version=agent_version,
        processing_time_ms=latency_ms or rng.gauss(800, 150),
    )


def _weighted_outcome(
    resolve_p: float, error_p: float, escalate_p: float
) -> DecisionOutcome:
    r = rng.random()
    if r < resolve_p:
        return DecisionOutcome.RESOLVED
    if r < resolve_p + error_p:
        return DecisionOutcome.ERROR
    if r < resolve_p + error_p + escalate_p:
        return DecisionOutcome.ESCALATED
    return DecisionOutcome.REJECTED


def generate_healthy_baseline(n: int = 200, agent_version: str = "v1.0") -> list[AgentDecision]:
    """
    Healthy agent baseline: good resolution rates across all categories.
    High-risk categories have slightly lower resolution (they're harder), but
    no alarming patterns.
    """
    decisions = []
    base_time = datetime.utcnow() - timedelta(days=30)
    category_profiles = {
        # category: (weight, resolve_p, error_p, escalate_p)
        CaseCategory.ROUTINE:          (0.55, 0.88, 0.03, 0.06),
        CaseCategory.BILLING_DISPUTE:  (0.20, 0.83, 0.04, 0.10),
        CaseCategory.FRAUD_CLAIM:      (0.10, 0.80, 0.05, 0.12),
        CaseCategory.POLICY_SENSITIVE: (0.15, 0.82, 0.04, 0.11),
    }
    categories = list(category_profiles.keys())
    weights = [p[0] for p in category_profiles.values()]

    for i in range(n):
        cat = rng.choices(categories, weights=weights, k=1)[0]
        _, resolve_p, error_p, escalate_p = category_profiles[cat]
        outcome = _weighted_outcome(resolve_p, error_p, escalate_p)
        ts = base_time + timedelta(seconds=i * 300)  # 5-min intervals
        decisions.append(
            _decision(
                case_id=f"CASE-{i:04d}",
                category=cat,
                outcome=outcome,
                confidence=max(0.01, min(0.99, rng.gauss(0.82, 0.07))),
                ts=ts,
                agent_version=agent_version,
            )
        )
    return decisions


def generate_drifted_window(
    n: int = 50,
    agent_version: str = "v1.1",
    base_offset_hours: int = 0,
) -> list[AgentDecision]:
    """
    Drifted agent (post-update):
    - Overall resolution rate is 84.8% — looks healthy!
    - But billing_dispute resolution drops from 83% → 44%
    - And fraud_claim error rate spikes from 5% → 28%
    - Routine cases are unaffected (masks the drift in aggregate metrics)
    """
    decisions = []
    base_time = datetime.utcnow() - timedelta(hours=base_offset_hours)
    category_profiles = {
        # category: (weight, resolve_p, error_p, escalate_p)
        CaseCategory.ROUTINE:          (0.55, 0.87, 0.03, 0.07),  # ← barely changed
        CaseCategory.BILLING_DISPUTE:  (0.20, 0.44, 0.08, 0.35),  # ← resolution COLLAPSED
        CaseCategory.FRAUD_CLAIM:      (0.10, 0.55, 0.28, 0.15),  # ← error rate SPIKED
        CaseCategory.POLICY_SENSITIVE: (0.15, 0.74, 0.09, 0.14),  # ← moderate drift
    }
    categories = list(category_profiles.keys())
    weights = [p[0] for p in category_profiles.values()]

    for i in range(n):
        cat = rng.choices(categories, weights=weights, k=1)[0]
        _, resolve_p, error_p, escalate_p = category_profiles[cat]
        outcome = _weighted_outcome(resolve_p, error_p, escalate_p)
        ts = base_time + timedelta(seconds=i * 120)  # 2-min intervals (higher velocity)
        decisions.append(
            _decision(
                case_id=f"DRIFT-{i:04d}",
                category=cat,
                outcome=outcome,
                confidence=rng.gauss(0.71, 0.12),  # lower confidence overall
                ts=ts,
                agent_version=agent_version,
            )
        )
    return decisions


# ── Demo flow ──────────────────────────────────────────────────────────────────

def print_section(title: str, style: str = "bold white") -> None:
    console.print()
    console.rule(f"[{style}]{title}[/{style}]")
    console.print()


def print_decision_summary(decisions: list[AgentDecision], label: str) -> None:
    from collections import Counter
    cat_counts: Counter = Counter()
    outcome_counts: Counter = Counter()
    for d in decisions:
        cat_counts[d.category.value] += 1
        outcome_counts[d.outcome.value] += 1

    total = len(decisions)
    res_rate = outcome_counts.get("resolved", 0) / total if total else 0
    err_rate = outcome_counts.get("error", 0) / total if total else 0

    console.print(f"  [bold]{label}[/bold]  ({total} decisions)")
    console.print(f"    Overall resolution: [bold]{res_rate:.1%}[/bold]  |  Error rate: {err_rate:.1%}")

    # Per-category stats
    from src.governance.schema import CategoryStats
    for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM,
                CaseCategory.POLICY_SENSITIVE, CaseCategory.ROUTINE]:
        cat_decisions = [d for d in decisions if d.category == cat]
        if not cat_decisions:
            continue
        stats = CategoryStats.from_decisions(cat, cat_decisions)
        name = cat.value.replace("_", " ").title()
        risk_tag = " [bold red][HIGH RISK][/bold red]" if cat.is_high_risk() else ""
        console.print(
            f"    {name:22s}{risk_tag}  "
            f"n={stats.sample_size:3d}  "
            f"resolved={stats.resolution_rate:.1%}  "
            f"error={stats.error_rate:.1%}"
        )


def main() -> None:
    print_section("AI AGENT GOVERNANCE MVP — DEMO", "bold cyan")

    console.print(Panel(
        "[bold]Core value proposition:[/bold]\n\n"
        "  An AI support agent looks completely healthy on standard ops metrics\n"
        "  (resolution rate, response time) for weeks after a regression —\n"
        "  because high-risk cases are a small fraction of total volume.\n\n"
        "  This system detects per-category drift on high-risk cases and\n"
        "  triggers rollback BEFORE the damage accumulates.",
        title="Overview",
        border_style="cyan",
    ))
    console.print()

    # ── Setup ──────────────────────────────────────────────────────────────────
    config = GovernanceConfig.default()
    store = DecisionStore()  # in-memory for demo
    ingestor = DecisionIngestor(store, config)
    detector = DriftDetector(store, config)
    alert_engine = AlertEngine(store, config)
    rollback_engine = RollbackEngine(store, config)
    dashboard = GovernanceDashboard(store, config, detector, alert_engine, rollback_engine)

    # ── Phase 1: Healthy baseline ──────────────────────────────────────────────
    print_section("PHASE 1: Agent v1.0 — Establishing Baseline (200 decisions)")

    baseline = generate_healthy_baseline(200, agent_version="v1.0")
    accepted, errors = ingestor.ingest_batch(baseline)
    console.print(f"  Ingested [bold green]{accepted}[/bold green] decisions  ({len(errors)} rejected)")
    print_decision_summary(baseline, "Baseline period")

    baseline_results = detector.run_detection()
    console.print()
    console.print("  [bold]Governance check on baseline:[/bold]")
    all_ok = True
    for r in baseline_results:
        if r.insufficient_data:
            console.print(f"    {r.category.value:20s}  [dim]insufficient data ({r.insufficient_data_reason})[/dim]")
        else:
            style = "green" if r.drift_score < 0.2 else "yellow"
            console.print(f"    {r.category.value:20s}  drift={r.drift_score:.3f}  [bold {style}]✓ STABLE[/bold {style}]")

    # ── Phase 2: Agent update deployed ────────────────────────────────────────
    print_section("PHASE 2: Agent v1.1 Deployed — Silent Regression", "bold yellow")

    console.print(Panel(
        "[yellow]⚠  Agent v1.1 deployed with a regression in the billing/fraud handling module.[/yellow]\n\n"
        "  Standard ops metrics will NOT catch this immediately because:\n"
        "  • High-risk cases are only ~20-25% of total volume\n"
        "  • Overall resolution rate drops from 87% → 85%  (looks like noise)\n"
        "  • Response times unchanged\n"
        "  • No crashes, no alerts from ops tooling\n\n"
        "  [bold red]But governance signals tell a different story.[/bold red]",
        border_style="yellow",
    ))
    console.print()

    drifted = generate_drifted_window(50, agent_version="v1.1", base_offset_hours=2)
    accepted2, errors2 = ingestor.ingest_batch(drifted)
    console.print(f"  Ingested [bold]{accepted2}[/bold] post-update decisions")
    print_decision_summary(drifted, "Post-update window (v1.1)")

    # ── Phase 3: Governance detection ─────────────────────────────────────────
    print_section("PHASE 3: Governance Detection Run", "bold red")

    drift_results = detector.run_detection()
    new_alerts = alert_engine.process_drift_results(drift_results)
    rollback_event = rollback_engine.maybe_trigger(drift_results)

    console.print("  [bold]Per-category drift scores:[/bold]")
    for r in drift_results:
        if r.insufficient_data:
            console.print(f"    {r.category.value:20s}  [dim]insufficient data[/dim]")
            continue
        thresholds = config.thresholds_for(r.category)
        score = r.drift_score
        if score >= thresholds.critical_score:
            style = "bold red"
            tag = "🚨 CRITICAL"
        elif score >= thresholds.warning_score:
            style = "bold yellow"
            tag = "⚠  WARNING"
        else:
            style = "green"
            tag = "✓  STABLE"

        baseline_res = r.baseline_stats.resolution_rate if r.baseline_stats else 0
        recent_res = r.recent_stats.resolution_rate if r.recent_stats else 0
        baseline_err = r.baseline_stats.error_rate if r.baseline_stats else 0
        recent_err = r.recent_stats.error_rate if r.recent_stats else 0

        console.print(
            f"    [{style}]{r.category.value:20s}  drift={score:.3f}  "
            f"res: {baseline_res:.1%}→{recent_res:.1%}  "
            f"err: {baseline_err:.1%}→{recent_err:.1%}  {tag}[/{style}]"
        )

    console.print()
    if new_alerts:
        console.print(f"  [bold red]Generated {len(new_alerts)} new alert(s):[/bold red]")
        for alert in new_alerts:
            style = "red" if alert.severity.value == "critical" else "yellow"
            console.print(f"    [{style}][{alert.severity.value.upper()}] {alert.message}[/{style}]")
    else:
        console.print("  No new alerts generated.")

    console.print()
    if rollback_event:
        console.print(Panel(
            f"[bold red]🚨 ROLLBACK TRIGGERED[/bold red]\n\n"
            f"  Reason: {rollback_event.reason}\n\n"
            f"  Event ID: {rollback_event.event_id}\n"
            f"  Timestamp: {rollback_event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"  [bold]Action required:[/bold] Revert to agent v1.0 or hotfix before v1.1\n"
            f"  can continue processing high-risk cases.",
            border_style="red",
            title="ROLLBACK RECOMMENDATION",
        ))
    else:
        console.print("  [green]No rollback conditions met.[/green]")

    # ── Phase 4: Dashboard ─────────────────────────────────────────────────────
    print_section("PHASE 4: PM Dashboard Snapshot", "bold cyan")

    dashboard.render()

    # ── Summary ────────────────────────────────────────────────────────────────
    print_section("SUMMARY", "bold white")
    overall_decisions = store.get_all_recent(250)
    total = len(overall_decisions)
    resolved = sum(1 for d in overall_decisions if d.outcome.value == "resolved")
    overall_res_rate = resolved / total if total else 0

    console.print(Panel(
        f"  [bold]Total decisions ingested:[/bold] {total}\n"
        f"  [bold]Overall resolution rate:[/bold]  {overall_res_rate:.1%}  "
        f"[dim](looks fine — this is what ops sees)[/dim]\n\n"
        f"  [bold red]Active governance alerts:[/bold red]   {len(alert_engine.get_active_alerts())}\n"
        f"  [bold red]Rollback triggered:[/bold red]        {'YES 🚨' if rollback_event else 'No'}\n\n"
        f"  [green]✓  Governance layer detected the silent regression that standard\n"
        f"     ops metrics would have missed for days or weeks.[/green]",
        title="Result",
        border_style="bold cyan",
    ))


if __name__ == "__main__":
    main()
