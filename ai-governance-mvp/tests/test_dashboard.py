"""Tests for GovernanceDashboard (src/dashboard/dashboard.py).

The dashboard has two concerns:
  1. Data computation — _compute_normal_metrics(), _compute_status()
  2. Rich panel construction — panel builders return Panel objects without crashing

We test both; we do NOT assert on terminal output strings because Rich
formatting is an implementation detail that changes with terminal width.
We verify the return types and semantic invariants instead.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

from src.dashboard.dashboard import GovernanceDashboard
from src.detection.detector import DriftDetector
from src.engine.alerts import AlertEngine
from src.engine.rollback import RollbackEngine
from src.governance.config import GovernanceConfig
from src.governance.schema import (
    CaseCategory,
    GovernanceStatus,
    NormalMetrics,
    RollbackEvent,
)
from src.ingestion.ingestor import DecisionIngestor
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def components():
    config = GovernanceConfig.default()
    store = DecisionStore()
    ingestor = DecisionIngestor(store, config)
    detector = DriftDetector(store, config)
    alert_engine = AlertEngine(store, config)
    rollback_engine = RollbackEngine(store, config)
    dashboard = GovernanceDashboard(store, config, detector, alert_engine, rollback_engine)
    return config, store, ingestor, detector, alert_engine, rollback_engine, dashboard


@pytest.fixture
def healthy_components():
    """Pre-populated store with healthy baseline and recent data."""
    config = GovernanceConfig.default()
    store = DecisionStore()
    ingestor = DecisionIngestor(store, config)
    detector = DriftDetector(store, config)
    alert_engine = AlertEngine(store, config)
    rollback_engine = RollbackEngine(store, config)
    dashboard = GovernanceDashboard(store, config, detector, alert_engine, rollback_engine)

    base = datetime.utcnow() - timedelta(days=15)
    recent = datetime.utcnow() - timedelta(hours=2)
    for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM,
                CaseCategory.POLICY_SENSITIVE, CaseCategory.ROUTINE]:
        store.store_decisions_batch(
            make_decision_batch(cat, n=40, resolve_p=0.83, error_p=0.04, escalate_p=0.10,
                                base_time=base)
        )
        store.store_decisions_batch(
            make_decision_batch(cat, n=15, resolve_p=0.83, error_p=0.04, escalate_p=0.10,
                                base_time=recent, time_step_seconds=60)
        )
    return config, store, ingestor, detector, alert_engine, rollback_engine, dashboard


# ── _compute_normal_metrics() ──────────────────────────────────────────────────

class TestComputeNormalMetrics:
    def test_returns_none_for_empty_store(self, components):
        *_, dashboard = components
        result = dashboard._compute_normal_metrics()
        assert result is None

    def test_returns_normal_metrics_with_data(self, healthy_components):
        *_, dashboard = healthy_components
        result = dashboard._compute_normal_metrics()
        assert result is not None
        assert isinstance(result, NormalMetrics)

    def test_resolution_rate_in_range(self, healthy_components):
        *_, dashboard = healthy_components
        nm = dashboard._compute_normal_metrics()
        assert 0.0 <= nm.overall_resolution_rate <= 1.0

    def test_error_rate_in_range(self, healthy_components):
        *_, dashboard = healthy_components
        nm = dashboard._compute_normal_metrics()
        assert 0.0 <= nm.overall_error_rate <= 1.0

    def test_rates_sum_le_one(self, healthy_components):
        *_, dashboard = healthy_components
        nm = dashboard._compute_normal_metrics()
        assert nm.overall_resolution_rate + nm.overall_error_rate + nm.overall_escalation_rate <= 1.001

    def test_total_volume_matches_store(self, healthy_components):
        config, store, *_, dashboard = healthy_components
        nm = dashboard._compute_normal_metrics()
        assert nm.total_volume == store.total_count()

    def test_high_risk_volume_is_subset_of_total(self, healthy_components):
        config, store, *_, dashboard = healthy_components
        nm = dashboard._compute_normal_metrics()
        assert nm.high_risk_volume <= nm.total_volume

    def test_p95_ge_mean_latency(self, healthy_components):
        *_, dashboard = healthy_components
        nm = dashboard._compute_normal_metrics()
        assert nm.p95_response_time_ms >= nm.mean_response_time_ms

    def test_healthy_agent_has_high_resolution_rate(self, healthy_components):
        *_, dashboard = healthy_components
        nm = dashboard._compute_normal_metrics()
        assert nm.overall_resolution_rate > 0.70

    def test_window_size_correct(self, components):
        config, store, ingestor, detector, alert_engine, rollback_engine, dashboard = components
        now = datetime.utcnow()
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 30, 0.85, 0.05, 0.08,
                                base_time=now - timedelta(hours=1), time_step_seconds=30)
        )
        nm = dashboard._compute_normal_metrics()
        assert nm.window_size == 30


# ── _compute_status() ─────────────────────────────────────────────────────────

class TestComputeStatus:
    def test_healthy_when_no_data(self, components):
        *_, detector, _, rollback_engine, dashboard = components
        drift_results = detector.run_detection()
        status = dashboard._compute_status(drift_results)
        assert status == GovernanceStatus.HEALTHY

    def test_healthy_with_healthy_data(self):
        """Use independent RNG to avoid conftest RNG state contamination."""
        import random as _random
        _rng = _random.Random(777)

        config = GovernanceConfig.default()
        store = DecisionStore()
        detector = DriftDetector(store, config)
        rollback_engine = RollbackEngine(store, config)
        dashboard = GovernanceDashboard(store, config, detector=detector,
                                        rollback_engine=rollback_engine)

        base = datetime.utcnow() - timedelta(days=15)
        recent = datetime.utcnow() - timedelta(hours=2)
        from src.governance.schema import AgentDecision, DecisionOutcome
        from src.ingestion.store import DecisionStore as DS

        def _batch(cat, n, base_time, resolve_p, error_p, escalate_p):
            decisions = []
            for i in range(n):
                r = _rng.random()
                if r < resolve_p:
                    outcome = DecisionOutcome.RESOLVED
                elif r < resolve_p + error_p:
                    outcome = DecisionOutcome.ERROR
                elif r < resolve_p + error_p + escalate_p:
                    outcome = DecisionOutcome.ESCALATED
                else:
                    outcome = DecisionOutcome.REJECTED
                ts = base_time + timedelta(seconds=i * 300)
                decisions.append(AgentDecision(
                    case_id=f"{cat.value}-{i}",
                    category=cat,
                    outcome=outcome,
                    confidence=max(0.01, min(0.99, _rng.gauss(0.82, 0.07))),
                    timestamp=ts,
                    agent_version="v1.0",
                    processing_time_ms=500.0,
                ))
            return decisions

        for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM,
                    CaseCategory.POLICY_SENSITIVE, CaseCategory.ROUTINE]:
            store.store_decisions_batch(
                _batch(cat, 40, base, 0.83, 0.04, 0.10)
            )
            store.store_decisions_batch(
                _batch(cat, 15, recent, 0.83, 0.04, 0.10)
            )

        drift_results = detector.run_detection()
        status = dashboard._compute_status(drift_results)
        assert status != GovernanceStatus.ROLLBACK_TRIGGERED

    def test_rollback_triggered_when_active(self, components):
        config, store, ingestor, detector, alert_engine, rollback_engine, dashboard = components
        event = RollbackEvent(
            reason="Critical regression",
            triggered_by="test",
            drift_score=1.0,
        )
        store.store_rollback_event(event)
        drift_results = detector.run_detection()
        status = dashboard._compute_status(drift_results)
        assert status == GovernanceStatus.ROLLBACK_TRIGGERED

    def test_critical_detected_with_drifted_data(self, components):
        config, store, ingestor, detector, alert_engine, rollback_engine, dashboard = components
        base = datetime.utcnow() - timedelta(days=15)
        recent = datetime.utcnow() - timedelta(hours=1)
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 50, 0.85, 0.04, 0.08,
                                base_time=base)
        )
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 15, 0.10, 0.65, 0.20,
                                base_time=recent, time_step_seconds=30)
        )
        drift_results = detector.run_detection()
        status = dashboard._compute_status(drift_results)
        assert status in (GovernanceStatus.CRITICAL, GovernanceStatus.DRIFTING)

    def test_rollback_takes_precedence_over_critical(self, components):
        config, store, ingestor, detector, alert_engine, rollback_engine, dashboard = components
        event = RollbackEvent(
            reason="Critical error rate",
            triggered_by="test",
            drift_score=1.0,
        )
        store.store_rollback_event(event)
        base = datetime.utcnow() - timedelta(days=15)
        recent = datetime.utcnow() - timedelta(hours=1)
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 50, 0.85, 0.04, 0.08, base_time=base)
        )
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 15, 0.10, 0.65, 0.20,
                                base_time=recent, time_step_seconds=30)
        )
        drift_results = detector.run_detection()
        status = dashboard._compute_status(drift_results)
        assert status == GovernanceStatus.ROLLBACK_TRIGGERED


# ── Panel builders ────────────────────────────────────────────────────────────

class TestPanelBuilders:
    def test_normal_metrics_panel_returns_panel_empty(self, components):
        *_, dashboard = components
        panel = dashboard._normal_metrics_panel(None)
        assert isinstance(panel, Panel)

    def test_normal_metrics_panel_returns_panel_with_data(self, healthy_components):
        *_, dashboard = healthy_components
        nm = dashboard._compute_normal_metrics()
        panel = dashboard._normal_metrics_panel(nm)
        assert isinstance(panel, Panel)

    def test_governance_panel_returns_panel_empty(self, components):
        *_, detector, _, _, dashboard = components
        drift_results = detector.run_detection()
        panel = dashboard._governance_panel(drift_results, GovernanceStatus.HEALTHY)
        assert isinstance(panel, Panel)

    def test_governance_panel_returns_panel_with_data(self, healthy_components):
        config, store, _, detector, alert_engine, rollback_engine, dashboard = healthy_components
        drift_results = detector.run_detection()
        panel = dashboard._governance_panel(drift_results, GovernanceStatus.HEALTHY)
        assert isinstance(panel, Panel)

    def test_alerts_panel_no_alerts(self, components):
        *_, alert_engine, _, dashboard = components
        alerts = alert_engine.get_active_alerts()
        panel = dashboard._alerts_panel(alerts)
        assert isinstance(panel, Panel)

    def test_alerts_panel_with_alerts(self, components):
        config, store, ingestor, detector, alert_engine, rollback_engine, dashboard = components
        base = datetime.utcnow() - timedelta(days=15)
        recent = datetime.utcnow() - timedelta(hours=1)
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 50, 0.85, 0.04, 0.08, base_time=base)
        )
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 15, 0.10, 0.65, 0.20,
                                base_time=recent, time_step_seconds=30)
        )
        drift_results = detector.run_detection()
        alerts = alert_engine.process_drift_results(drift_results)
        panel = dashboard._alerts_panel(alerts)
        assert isinstance(panel, Panel)

    def test_rollback_panel_with_events(self, components):
        config, store, _, detector, alert_engine, rollback_engine, dashboard = components
        event = RollbackEvent(
            reason="Regression detected",
            triggered_by="test",
            drift_score=0.9,
        )
        store.store_rollback_event(event)
        events = rollback_engine.get_rollback_history()
        panel = dashboard._rollback_panel(events)
        assert isinstance(panel, Panel)

    def test_build_header_returns_panel(self, components):
        *_, dashboard = components
        for status in GovernanceStatus:
            panel = dashboard._build_header(status)
            assert isinstance(panel, Panel)


# ── _build_full_layout() ───────────────────────────────────────────────────────

class TestBuildFullLayout:
    def test_returns_something_renderable(self, components):
        *_, dashboard = components
        layout = dashboard._build_full_layout()
        assert layout is not None

    def test_includes_rollback_section_when_active(self, components):
        config, store, *_, dashboard = components
        event = RollbackEvent(
            reason="Test regression",
            triggered_by="test",
            drift_score=0.95,
        )
        store.store_rollback_event(event)
        from rich.console import Group
        layout = dashboard._build_full_layout()
        assert isinstance(layout, Group)


# ── render() smoke test ────────────────────────────────────────────────────────

class TestRender:
    def test_render_does_not_raise_empty_store(self, components, capsys):
        *_, dashboard = components
        from rich.console import Console
        import io
        dashboard._console = Console(file=io.StringIO(), force_terminal=True)
        # render() uses the module-level console; patch it temporarily
        import src.dashboard.dashboard as mod
        old = mod.console
        mod.console = Console(file=io.StringIO(), force_terminal=True)
        try:
            dashboard.render()
        finally:
            mod.console = old

    def test_render_does_not_raise_with_data(self, healthy_components, capsys):
        from rich.console import Console as RichConsole
        *_, dashboard = healthy_components
        import src.dashboard.dashboard as mod
        import io
        old = mod.console
        mod.console = RichConsole(file=io.StringIO(), force_terminal=True)
        try:
            dashboard.render()
        finally:
            mod.console = old

    def test_render_with_active_rollback(self, components):
        config, store, *_, dashboard = components
        event = RollbackEvent(reason="Regression", triggered_by="test", drift_score=1.0)
        store.store_rollback_event(event)
        import src.dashboard.dashboard as mod
        import io
        from rich.console import Console
        old = mod.console
        mod.console = Console(file=io.StringIO(), force_terminal=True)
        try:
            dashboard.render()
        finally:
            mod.console = old


# ── Default constructor (no explicit sub-components) ──────────────────────────

class TestDefaultConstruction:
    def test_default_construction_works(self):
        config = GovernanceConfig.default()
        store = DecisionStore()
        dashboard = GovernanceDashboard(store, config)
        assert dashboard is not None

    def test_default_construction_computes_status(self):
        config = GovernanceConfig.default()
        store = DecisionStore()
        dashboard = GovernanceDashboard(store, config)
        drift_results = dashboard._detector.run_detection()
        status = dashboard._compute_status(drift_results)
        assert status == GovernanceStatus.HEALTHY


# ── Side-by-side: normal metrics mask governance drift ────────────────────────

class TestSideBySideContrast:
    """Verify the dashboard correctly surfaces the core value proposition:
    governance sees what normal metrics hide."""

    def test_normal_looks_ok_while_governance_critical(self):
        """Overall resolution looks healthy. Governance shows CRITICAL on fraud."""
        config = GovernanceConfig.default()
        store = DecisionStore()
        ingestor = DecisionIngestor(store, config)
        detector = DriftDetector(store, config)
        alert_engine = AlertEngine(store, config)
        rollback_engine = RollbackEngine(store, config)
        dashboard = GovernanceDashboard(store, config, detector, alert_engine, rollback_engine)

        base = datetime.utcnow() - timedelta(days=15)
        recent = datetime.utcnow() - timedelta(hours=2)

        # Large healthy routine volume (masks the fraud drift in blended metrics)
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 150, 0.90, 0.02, 0.05, base_time=base)
        )
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 50, 0.90, 0.02, 0.05,
                                base_time=recent, time_step_seconds=30)
        )
        # Fraud baseline (healthy)
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.FRAUD_CLAIM, 30, 0.85, 0.04, 0.08, base_time=base)
        )
        # Fraud recent (severely broken)
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.FRAUD_CLAIM, 12, 0.10, 0.70, 0.15,
                                base_time=recent, time_step_seconds=60)
        )

        nm = dashboard._compute_normal_metrics()
        drift_results = detector.run_detection()
        gov_status = dashboard._compute_status(drift_results)

        # Normal metrics still look OK due to routine volume
        assert nm is not None
        assert nm.overall_resolution_rate > 0.70, (
            f"Normal metrics should look fine, got {nm.overall_resolution_rate:.1%}"
        )

        # Governance detects the fraud drift
        fraud_result = next(
            (r for r in drift_results
             if r.category == CaseCategory.FRAUD_CLAIM and not r.insufficient_data),
            None,
        )
        assert fraud_result is not None, "Fraud drift result should exist"
        assert fraud_result.drift_score > 0.0, "Governance should detect drift on fraud"
        assert gov_status in (GovernanceStatus.CRITICAL, GovernanceStatus.DRIFTING), (
            f"Governance should flag an issue, got {gov_status}"
        )
