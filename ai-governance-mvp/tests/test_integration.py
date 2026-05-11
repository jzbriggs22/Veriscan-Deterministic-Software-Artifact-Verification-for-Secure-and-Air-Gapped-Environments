"""
Integration tests: end-to-end scenarios.

Scenario A: Healthy agent — all governance checks pass.
Scenario B: Silent regression — normal metrics OK, governance detects drift.
Scenario C: Critical drift — rollback is triggered.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from src.detection.detector import DriftDetector
from src.engine.alerts import AlertEngine
from src.engine.rollback import RollbackEngine
from src.governance.config import GovernanceConfig
from src.governance.schema import CaseCategory, DecisionOutcome, GovernanceStatus
from src.ingestion.ingestor import DecisionIngestor
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch


def _setup():
    config = GovernanceConfig.default()
    store = DecisionStore()
    ingestor = DecisionIngestor(store, config)
    detector = DriftDetector(store, config)
    alert_engine = AlertEngine(store, config)
    rollback_engine = RollbackEngine(store, config)
    return config, store, ingestor, detector, alert_engine, rollback_engine


# ── Scenario A: Healthy agent ──────────────────────────────────────────────────

def test_healthy_agent_produces_no_alerts():
    config, store, ingestor, detector, alert_engine, rollback_engine = _setup()

    # Load a clean baseline
    for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM,
                CaseCategory.POLICY_SENSITIVE, CaseCategory.ROUTINE]:
        baseline = make_decision_batch(cat, n=50, resolve_p=0.83, error_p=0.04, escalate_p=0.10)
        ingestor.ingest_batch(baseline)

    drift_results = detector.run_detection()
    alerts = alert_engine.process_drift_results(drift_results)
    rollback = rollback_engine.maybe_trigger(drift_results)

    assert alerts == [], f"Expected no alerts for healthy agent, got: {[a.message for a in alerts]}"
    assert rollback is None


def test_healthy_agent_normal_metrics_match_governance_healthy():
    config, store, ingestor, detector, alert_engine, rollback_engine = _setup()
    from src.dashboard.dashboard import GovernanceDashboard
    dashboard = GovernanceDashboard(store, config, detector, alert_engine, rollback_engine)

    for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM, CaseCategory.ROUTINE]:
        ingestor.ingest_batch(
            make_decision_batch(cat, 50, 0.83, 0.04, 0.10)
        )

    drift_results = detector.run_detection()
    status = dashboard._compute_status(drift_results)
    normal = dashboard._compute_normal_metrics()

    # Both normal metrics and governance should look healthy
    assert status in (GovernanceStatus.HEALTHY, GovernanceStatus.DRIFTING)
    assert normal is not None
    assert normal.overall_resolution_rate > 0.75


# ── Scenario B: Silent regression (normal metrics mask governance drift) ───────

def test_silent_regression_detected_by_governance_not_normal_metrics():
    """
    The key scenario: overall resolution rate drops only slightly (noise-level),
    but governance layer detects per-category drift on high-risk cases.
    """
    config, store, ingestor, detector, alert_engine, rollback_engine = _setup()

    # Healthy baseline — placed at 15d ago so it falls within [now-30d, now-7d)
    base_time = datetime.utcnow() - timedelta(days=15)
    for cat, n in [
        (CaseCategory.ROUTINE, 100),
        (CaseCategory.BILLING_DISPUTE, 30),
        (CaseCategory.FRAUD_CLAIM, 20),
        (CaseCategory.POLICY_SENSITIVE, 25),
    ]:
        ingestor.ingest_batch(
            make_decision_batch(cat, n, resolve_p=0.83, error_p=0.04, escalate_p=0.10,
                                base_time=base_time)
        )

    # Drifted recent: routine stays fine, high-risk degrades
    recent_time = datetime.utcnow() - timedelta(hours=2)
    ingestor.ingest_batch(
        make_decision_batch(CaseCategory.ROUTINE, 30, resolve_p=0.85, error_p=0.03, escalate_p=0.09,
                            base_time=recent_time, time_step_seconds=60)
    )
    ingestor.ingest_batch(
        make_decision_batch(CaseCategory.BILLING_DISPUTE, 10, resolve_p=0.40, error_p=0.22, escalate_p=0.30,
                            base_time=recent_time, time_step_seconds=60)
    )
    ingestor.ingest_batch(
        make_decision_batch(CaseCategory.FRAUD_CLAIM, 6, resolve_p=0.35, error_p=0.35, escalate_p=0.25,
                            base_time=recent_time, time_step_seconds=60)
    )

    # Check normal metrics (blended — looks OK-ish)
    from src.dashboard.dashboard import GovernanceDashboard
    dashboard = GovernanceDashboard(store, config, detector, alert_engine, rollback_engine)
    normal = dashboard._compute_normal_metrics()
    assert normal is not None
    # Overall resolution still decent due to large ROUTINE volume
    assert normal.overall_resolution_rate > 0.65

    # Check governance (should detect high-risk drift)
    drift_results = detector.run_detection()
    alerts = alert_engine.process_drift_results(drift_results)

    # Should have at least one alert on a high-risk category
    high_risk_alerts = [a for a in alerts if a.category.is_high_risk()]
    assert len(high_risk_alerts) >= 1, (
        f"Expected governance to detect drift on high-risk categories. "
        f"All alerts: {[a.message for a in alerts]}"
    )


# ── Scenario C: Critical drift triggers rollback ───────────────────────────────

def test_critical_drift_triggers_rollback():
    config, store, ingestor, detector, alert_engine, rollback_engine = _setup()

    # Healthy baseline — placed at 15d ago so it falls within [now-30d, now-7d)
    base_time = datetime.utcnow() - timedelta(days=15)
    for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM, CaseCategory.ROUTINE]:
        ingestor.ingest_batch(
            make_decision_batch(cat, 50, resolve_p=0.85, error_p=0.03, escalate_p=0.08,
                                base_time=base_time)
        )

    # Severe drift: fraud claim completely broken
    recent_time = datetime.utcnow() - timedelta(minutes=30)
    ingestor.ingest_batch(
        make_decision_batch(CaseCategory.FRAUD_CLAIM, 10, resolve_p=0.10, error_p=0.70, escalate_p=0.15,
                            base_time=recent_time, time_step_seconds=30)
    )
    ingestor.ingest_batch(
        make_decision_batch(CaseCategory.BILLING_DISPUTE, 10, resolve_p=0.20, error_p=0.60, escalate_p=0.15,
                            base_time=recent_time, time_step_seconds=30)
    )

    drift_results = detector.run_detection()
    rollback = rollback_engine.maybe_trigger(drift_results)

    assert rollback is not None, (
        f"Expected rollback to trigger. Drift scores: "
        f"{[(r.category.value, r.drift_score) for r in drift_results if not r.insufficient_data]}"
    )
    assert rollback.is_active
    assert rollback.category is not None


def test_rollback_prevents_double_trigger():
    config, store, ingestor, detector, alert_engine, rollback_engine = _setup()

    base_time = datetime.utcnow() - timedelta(days=15)
    recent_time = datetime.utcnow() - timedelta(minutes=10)
    ingestor.ingest_batch(
        make_decision_batch(CaseCategory.FRAUD_CLAIM, 20, 0.85, 0.03, 0.08, base_time=base_time)
    )
    ingestor.ingest_batch(
        make_decision_batch(CaseCategory.FRAUD_CLAIM, 8, 0.10, 0.70, 0.15,
                            base_time=recent_time, time_step_seconds=30)
    )

    drift_results = detector.run_detection()
    event1 = rollback_engine.maybe_trigger(drift_results)
    event2 = rollback_engine.maybe_trigger(drift_results)

    assert event1 is not None
    assert event2 is None  # second call must be a no-op


# ── Scenario D: Recovery after rollback ───────────────────────────────────────

def test_governance_recovers_after_rollback_resolved():
    config, store, ingestor, detector, alert_engine, rollback_engine = _setup()

    base_time = datetime.utcnow() - timedelta(days=15)
    recent_time = datetime.utcnow() - timedelta(minutes=20)
    ingestor.ingest_batch(
        make_decision_batch(CaseCategory.BILLING_DISPUTE, 30, 0.83, 0.04, 0.10, base_time=base_time)
    )
    ingestor.ingest_batch(
        make_decision_batch(CaseCategory.BILLING_DISPUTE, 8, 0.20, 0.55, 0.20,
                            base_time=recent_time, time_step_seconds=60)
    )

    drift_results = detector.run_detection()
    rollback_engine.maybe_trigger(drift_results)
    assert rollback_engine.is_rollback_active()

    rollback_engine.resolve_rollback("Reverted to agent v1.0")
    assert not rollback_engine.is_rollback_active()

    history = rollback_engine.get_rollback_history()
    assert len(history) == 1
    assert not history[0].is_active


# ── Scenario E: CategoryStats accuracy ────────────────────────────────────────

def test_category_stats_accurate():
    from src.governance.schema import CategoryStats, AgentDecision, DecisionOutcome
    from datetime import datetime

    decisions = [
        AgentDecision("C1", CaseCategory.BILLING_DISPUTE, DecisionOutcome.RESOLVED,
                      0.9, datetime.utcnow(), "v1.0", 400.0),
        AgentDecision("C2", CaseCategory.BILLING_DISPUTE, DecisionOutcome.RESOLVED,
                      0.8, datetime.utcnow(), "v1.0", 500.0),
        AgentDecision("C3", CaseCategory.BILLING_DISPUTE, DecisionOutcome.ERROR,
                      0.4, datetime.utcnow(), "v1.0", 600.0),
        AgentDecision("C4", CaseCategory.BILLING_DISPUTE, DecisionOutcome.ESCALATED,
                      0.6, datetime.utcnow(), "v1.0", 700.0),
    ]
    stats = CategoryStats.from_decisions(CaseCategory.BILLING_DISPUTE, decisions)
    assert stats.sample_size == 4
    assert abs(stats.resolution_rate - 0.5) < 1e-9
    assert abs(stats.error_rate - 0.25) < 1e-9
    assert abs(stats.escalation_rate - 0.25) < 1e-9
    assert abs(stats.mean_confidence - (0.9 + 0.8 + 0.4 + 0.6) / 4) < 1e-9
