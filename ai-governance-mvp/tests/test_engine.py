"""Tests for alert engine and rollback engine."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from src.detection.detector import DriftDetector
from src.engine.alerts import AlertEngine
from src.engine.rollback import RollbackEngine
from src.governance.schema import (
    AlertSeverity,
    CaseCategory,
    CategoryStats,
    DecisionOutcome,
    DriftResult,
)
from tests.conftest import make_decision_batch


# ── Helpers ────────────────────────────────────────────────────────────────────

def _drift_result(
    category: CaseCategory = CaseCategory.BILLING_DISPUTE,
    drift_score: float = 0.0,
    error_rate: float = 0.05,
    resolution_rate: float = 0.80,
) -> DriftResult:
    """Build a synthetic DriftResult for testing without hitting the store."""
    from src.governance.schema import AgentDecision, DecisionOutcome
    import uuid

    n_baseline = 50
    n_recent = 20

    baseline_stats = CategoryStats(
        category=category,
        sample_size=n_baseline,
        resolution_rate=resolution_rate,
        escalation_rate=0.10,
        error_rate=0.04,
        mean_confidence=0.83,
        p50_latency_ms=500.0,
        resolved_count=int(n_baseline * resolution_rate),
        error_count=int(n_baseline * 0.04),
        escalation_count=int(n_baseline * 0.10),
    )
    recent_stats = CategoryStats(
        category=category,
        sample_size=n_recent,
        resolution_rate=max(0.0, resolution_rate - drift_score * 0.5),
        escalation_rate=0.15,
        error_rate=error_rate,
        mean_confidence=0.70,
        p50_latency_ms=600.0,
        resolved_count=int(n_recent * max(0, resolution_rate - drift_score * 0.5)),
        error_count=int(n_recent * error_rate),
        escalation_count=int(n_recent * 0.15),
    )
    return DriftResult(
        category=category,
        drift_score=drift_score,
        baseline_stats=baseline_stats,
        recent_stats=recent_stats,
        insufficient_data=False,
    )


# ── AlertEngine ────────────────────────────────────────────────────────────────

def test_no_alert_below_warning_threshold(config, store):
    engine = AlertEngine(store, config)
    result = _drift_result(drift_score=0.20)  # below warning (0.35 for billing)
    alerts = engine.process_drift_results([result])
    assert alerts == []


def test_warning_alert_at_warning_threshold(config, store):
    engine = AlertEngine(store, config)
    result = _drift_result(drift_score=0.50)  # above warning, below critical
    alerts = engine.process_drift_results([result])
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.WARNING


def test_critical_alert_at_critical_threshold(config, store):
    engine = AlertEngine(store, config)
    result = _drift_result(drift_score=0.80)  # above critical
    alerts = engine.process_drift_results([result])
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL


def test_error_rate_ceiling_triggers_critical_for_high_risk(config, store):
    engine = AlertEngine(store, config)
    # Error rate 0.20 > max_error_rate (0.12 for billing), score might be low
    result = _drift_result(
        category=CaseCategory.BILLING_DISPUTE,
        drift_score=0.10,  # low drift score
        error_rate=0.20,   # but error rate above ceiling
    )
    alerts = engine.process_drift_results([result])
    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL


def test_error_rate_ceiling_does_not_trigger_for_non_high_risk(config, store):
    engine = AlertEngine(store, config)
    # ROUTINE is not high-risk; error ceiling check skipped
    result = _drift_result(
        category=CaseCategory.ROUTINE,
        drift_score=0.10,
        error_rate=0.20,
    )
    alerts = engine.process_drift_results([result])
    # No alert because routine is not high-risk and drift_score < warning threshold
    assert alerts == []


def test_insufficient_data_skipped(config, store):
    engine = AlertEngine(store, config)
    result = DriftResult(
        category=CaseCategory.FRAUD_CLAIM,
        drift_score=0.0,
        insufficient_data=True,
        insufficient_data_reason="not enough data",
    )
    alerts = engine.process_drift_results([result])
    assert alerts == []


def test_alerts_persisted_to_store(config, store):
    engine = AlertEngine(store, config)
    result = _drift_result(drift_score=0.80)
    alerts = engine.process_drift_results([result])
    assert len(alerts) == 1
    active = store.get_active_alerts()
    assert len(active) == 1
    assert active[0].alert_id == alerts[0].alert_id


def test_alert_message_contains_category(config, store):
    engine = AlertEngine(store, config)
    result = _drift_result(category=CaseCategory.FRAUD_CLAIM, drift_score=0.80)
    alerts = engine.process_drift_results([result])
    assert "Fraud" in alerts[0].message or "fraud" in alerts[0].message


# ── RollbackEngine ─────────────────────────────────────────────────────────────

def test_no_rollback_for_healthy_results(config, store):
    engine = RollbackEngine(store, config)
    result = _drift_result(drift_score=0.20, error_rate=0.05)
    should, reason, _ = engine.evaluate([result])
    assert not should
    assert reason is None


def test_rollback_triggered_by_high_drift_score(config, store):
    engine = RollbackEngine(store, config)
    result = _drift_result(
        category=CaseCategory.BILLING_DISPUTE,
        drift_score=0.80,  # > 0.70 rollback threshold
        error_rate=0.05,
    )
    should, reason, triggering = engine.evaluate([result])
    assert should
    assert reason is not None
    assert triggering is not None
    assert "drift_score" in reason.lower() or "critical" in reason.lower()


def test_rollback_triggered_by_high_error_rate(config, store):
    engine = RollbackEngine(store, config)
    result = _drift_result(
        category=CaseCategory.FRAUD_CLAIM,
        drift_score=0.30,  # low drift score
        error_rate=0.22,   # > 0.15 error rate threshold
    )
    should, reason, _ = engine.evaluate([result])
    assert should
    assert "error_rate" in reason.lower() or "error" in reason.lower()


def test_rollback_not_triggered_for_routine_category(config, store):
    engine = RollbackEngine(store, config)
    # ROUTINE is not high-risk; rollback should not trigger for it
    result = _drift_result(
        category=CaseCategory.ROUTINE,
        drift_score=0.90,
        error_rate=0.30,
    )
    # Override is_high_risk by using a non-high-risk category
    should, reason, _ = engine.evaluate([result])
    # ROUTINE is not high-risk so rollback should not trigger
    assert not should


def test_maybe_trigger_creates_rollback_event(config, store):
    engine = RollbackEngine(store, config)
    result = _drift_result(drift_score=0.80)
    event = engine.maybe_trigger([result])
    assert event is not None
    assert event.is_active
    assert store.get_active_rollback() is not None


def test_maybe_trigger_skips_if_already_active(config, store):
    engine = RollbackEngine(store, config)
    result = _drift_result(drift_score=0.80)
    event1 = engine.maybe_trigger([result])
    assert event1 is not None
    # Second call should be skipped since rollback is already active
    event2 = engine.maybe_trigger([result])
    assert event2 is None


def test_resolve_rollback(config, store):
    engine = RollbackEngine(store, config)
    result = _drift_result(drift_score=0.80)
    engine.maybe_trigger([result])
    assert engine.is_rollback_active()
    engine.resolve_rollback("reverted to v1.0")
    assert not engine.is_rollback_active()


def test_rollback_history_preserved(config, store):
    engine = RollbackEngine(store, config)
    result = _drift_result(drift_score=0.80)
    engine.maybe_trigger([result])
    engine.resolve_rollback("reverted")
    history = engine.get_rollback_history()
    assert len(history) == 1
    assert history[0].resolution_note == "reverted"
