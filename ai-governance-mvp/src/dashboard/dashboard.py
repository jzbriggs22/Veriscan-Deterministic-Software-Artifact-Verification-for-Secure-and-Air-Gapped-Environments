"""
PM-facing governance dashboard.

Side-by-side view:  Normal metrics (resolution rate, response time, volume)
                    vs Governance signals (drift score, high-risk accuracy,
                       active alerts, rollback status).

Uses Rich for terminal rendering. Call dashboard.render() for a one-shot
snapshot, or dashboard.live(refresh_seconds=5) for auto-refresh.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..detection.detector import DriftDetector
from ..engine.alerts import AlertEngine
from ..engine.rollback import RollbackEngine
from ..governance.config import GovernanceConfig
from ..governance.schema import (
    AlertSeverity,
    CaseCategory,
    DriftResult,
    GovernanceStatus,
    NormalMetrics,
)
from ..governance.status import compute_status
from ..ingestion.store import DecisionStore

console = Console()

_STATUS_STYLE = {
    GovernanceStatus.HEALTHY: "bold green",
    GovernanceStatus.DRIFTING: "bold yellow",
    GovernanceStatus.CRITICAL: "bold red",
    GovernanceStatus.ROLLBACK_TRIGGERED: "bold white on red",
}

_SEVERITY_STYLE = {
    AlertSeverity.INFO: "cyan",
    AlertSeverity.WARNING: "yellow",
    AlertSeverity.CRITICAL: "bold red",
}


def _pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def _score_style(score: float, warn: float = 0.4, crit: float = 0.7) -> str:
    if score >= crit:
        return "bold red"
    if score >= warn:
        return "yellow"
    return "green"


class GovernanceDashboard:
    def __init__(
        self,
        store: DecisionStore,
        config: GovernanceConfig,
        detector: Optional[DriftDetector] = None,
        alert_engine: Optional[AlertEngine] = None,
        rollback_engine: Optional[RollbackEngine] = None,
    ) -> None:
        self._store = store
        self._config = config
        self._detector = detector or DriftDetector(store, config)
        self._alert_engine = alert_engine or AlertEngine(store, config)
        self._rollback_engine = rollback_engine or RollbackEngine(store, config)

    # ── Public API ─────────────────────────────────────────────────────────────

    def render(self) -> None:
        """Print a full one-shot governance report to the terminal."""
        drift_results = self._detector.run_detection()
        active_alerts = self._alert_engine.get_active_alerts()
        rollback_events = self._rollback_engine.get_rollback_history()
        normal = self._compute_normal_metrics()
        status = self._compute_status(drift_results)

        console.print(self._build_header(status))
        console.print()
        console.print(
            Columns(
                [
                    self._normal_metrics_panel(normal),
                    self._governance_panel(drift_results, status),
                ],
                equal=True,
                expand=True,
            )
        )
        console.print()
        console.print(self._alerts_panel(active_alerts))
        if rollback_events:
            console.print()
            console.print(self._rollback_panel(rollback_events))

    def live(self, refresh_seconds: float = 5.0, iterations: int = 0) -> None:
        """Auto-refreshing dashboard. iterations=0 means run forever."""
        count = 0
        with Live(console=console, refresh_per_second=1, screen=True) as live:
            while True:
                live.update(self._build_full_layout())
                count += 1
                if iterations and count >= iterations:
                    break
                time.sleep(refresh_seconds)

    # ── Panel builders ─────────────────────────────────────────────────────────

    def _build_header(self, status: GovernanceStatus) -> Panel:
        style = _STATUS_STYLE[status]
        title = Text(
            f"  AI AGENT GOVERNANCE DASHBOARD  ·  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            style="bold white",
        )
        status_text = Text(f"  STATUS: {status.value.upper().replace('_', ' ')}  ", style=style)
        header = Table.grid(expand=True)
        header.add_column(ratio=3)
        header.add_column(ratio=1, justify="right")
        header.add_row(title, status_text)
        return Panel(header, box=box.DOUBLE_EDGE, style=style.split()[-1])

    def _normal_metrics_panel(self, normal: Optional[NormalMetrics]) -> Panel:
        table = Table(box=box.SIMPLE, show_header=False, expand=True)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        if normal is None:
            table.add_row("No data", "–")
        else:
            res_style = "green" if normal.overall_resolution_rate >= 0.80 else "yellow"
            err_style = "green" if normal.overall_error_rate <= 0.05 else "red"

            table.add_row(
                "Resolution Rate",
                Text(_pct(normal.overall_resolution_rate), style=res_style),
            )
            table.add_row(
                "Error Rate",
                Text(_pct(normal.overall_error_rate), style=err_style),
            )
            table.add_row(
                "Escalation Rate",
                Text(_pct(normal.overall_escalation_rate), style="cyan"),
            )
            table.add_row(
                "Avg Response",
                f"{normal.mean_response_time_ms:.0f} ms",
            )
            table.add_row(
                "p95 Response",
                f"{normal.p95_response_time_ms:.0f} ms",
            )
            table.add_row("Total Volume", f"{normal.total_volume:,}")
            table.add_row(
                "  High-Risk Volume",
                Text(f"{normal.high_risk_volume:,}", style="yellow"),
            )
            table.add_row("Uptime", f"{normal.uptime_pct:.1f}%")

        return Panel(
            table,
            title="[bold]NORMAL METRICS[/bold]  [dim](what ops sees)[/dim]",
            border_style="blue",
            expand=True,
        )

    def _governance_panel(
        self, drift_results: list[DriftResult], status: GovernanceStatus
    ) -> Panel:
        table = Table(box=box.SIMPLE, show_header=True, expand=True)
        table.add_column("Category", style="bold")
        table.add_column("Drift", justify="right")
        table.add_column("Err Rate", justify="right")
        table.add_column("Res Rate", justify="right")
        table.add_column("Signal")

        for result in drift_results:
            if result.insufficient_data:
                cat_name = result.category.value.replace("_", " ").title()
                table.add_row(
                    cat_name,
                    "–",
                    "–",
                    "–",
                    Text(f"⚠ {result.insufficient_data_reason[:30]}", style="dim yellow"),
                )
                continue

            cat_name = next(
                (h.display_name for h in self._config.high_risk_categories if h.category == result.category),
                result.category.value.replace("_", " ").title(),
            )
            thresholds = self._config.thresholds_for(result.category)
            score = result.drift_score
            score_style = _score_style(score, thresholds.warning_score, thresholds.critical_score)

            err_rate = result.recent_stats.error_rate if result.recent_stats else 0.0
            res_rate = result.recent_stats.resolution_rate if result.recent_stats else 0.0
            err_style = "red" if err_rate > thresholds.max_error_rate else "green"

            if score >= thresholds.critical_score:
                signal = Text("🚨 CRITICAL", style="bold red")
            elif score >= thresholds.warning_score:
                signal = Text("⚠  DRIFTING", style="yellow")
            else:
                signal = Text("✓  STABLE", style="green")

            risk_prefix = "[bold red]★[/bold red] " if result.is_high_risk else "  "

            table.add_row(
                Text.from_markup(f"{risk_prefix}{cat_name}"),
                Text(f"{score:.2f}", style=score_style),
                Text(_pct(err_rate), style=err_style),
                Text(_pct(res_rate)),
                signal,
            )

        subtitle = (
            "[dim]★ = high-risk category  |  drift score 0.0–1.0[/dim]"
        )
        return Panel(
            table,
            title=f"[bold]GOVERNANCE SIGNALS[/bold]  [dim](what governance sees)[/dim]",
            subtitle=subtitle,
            border_style="red" if status in (GovernanceStatus.CRITICAL, GovernanceStatus.ROLLBACK_TRIGGERED) else "green",
            expand=True,
        )

    def _alerts_panel(self, active_alerts) -> Panel:
        if not active_alerts:
            return Panel(
                Text("No active alerts — all governance checks passing.", style="green"),
                title="[bold]ACTIVE ALERTS[/bold]",
                border_style="green",
            )

        table = Table(box=box.SIMPLE, show_header=True, expand=True)
        table.add_column("Time", style="dim")
        table.add_column("Sev")
        table.add_column("Message")

        for alert in active_alerts[:10]:
            sev_style = _SEVERITY_STYLE.get(alert.severity, "white")
            table.add_row(
                alert.timestamp.strftime("%H:%M:%S"),
                Text(alert.severity.value.upper(), style=sev_style),
                alert.message,
            )

        return Panel(
            table,
            title=f"[bold]ACTIVE ALERTS[/bold]  ({len(active_alerts)} unacknowledged)",
            border_style="yellow",
        )

    def _rollback_panel(self, rollback_events) -> Panel:
        table = Table(box=box.SIMPLE, show_header=True, expand=True)
        table.add_column("Time", style="dim")
        table.add_column("State")
        table.add_column("Reason")

        for event in rollback_events[:5]:
            state = Text("ACTIVE 🚨", style="bold red") if event.is_active else Text("resolved", style="green")
            table.add_row(
                event.timestamp.strftime("%Y-%m-%d %H:%M"),
                state,
                event.reason[:80],
            )

        return Panel(
            table,
            title="[bold]ROLLBACK EVENTS[/bold]",
            border_style="red",
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _compute_normal_metrics(self) -> Optional[NormalMetrics]:
        decisions = self._store.get_normal_metrics_window(200)
        if not decisions:
            return None
        n = len(decisions)
        from ..governance.schema import CaseCategory, DecisionOutcome
        resolved = sum(1 for d in decisions if d.outcome == DecisionOutcome.RESOLVED)
        errors = sum(1 for d in decisions if d.outcome == DecisionOutcome.ERROR)
        escalated = sum(1 for d in decisions if d.outcome == DecisionOutcome.ESCALATED)
        latencies = sorted(d.processing_time_ms for d in decisions)
        p95_idx = int(n * 0.95)
        high_risk = sum(1 for d in decisions if d.category.is_high_risk())
        return NormalMetrics(
            window_size=n,
            overall_resolution_rate=resolved / n,
            overall_error_rate=errors / n,
            overall_escalation_rate=escalated / n,
            mean_response_time_ms=sum(latencies) / n,
            p95_response_time_ms=latencies[min(p95_idx, n - 1)],
            total_volume=self._store.total_count(),
            high_risk_volume=high_risk,
        )

    def _compute_status(self, drift_results: list[DriftResult]) -> GovernanceStatus:
        return compute_status(
            drift_results,
            self._config,
            self._rollback_engine.is_rollback_active(),
        )

    def _build_full_layout(self):
        """For live mode: returns a renderable."""
        drift_results = self._detector.run_detection()
        active_alerts = self._alert_engine.get_active_alerts()
        rollback_events = self._rollback_engine.get_rollback_history()
        normal = self._compute_normal_metrics()
        status = self._compute_status(drift_results)

        from rich.console import Group
        parts = [
            self._build_header(status),
            Columns(
                [self._normal_metrics_panel(normal), self._governance_panel(drift_results, status)],
                equal=True,
                expand=True,
            ),
            self._alerts_panel(active_alerts),
        ]
        if rollback_events:
            parts.append(self._rollback_panel(rollback_events))
        return Group(*parts)
