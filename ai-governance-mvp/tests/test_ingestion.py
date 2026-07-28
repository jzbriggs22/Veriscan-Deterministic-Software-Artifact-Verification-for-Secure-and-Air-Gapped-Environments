"""Tests for ingestion layer: validation, categorization, and store operations."""
from __future__ import annotations

from datetime import datetime

import pytest

from src.governance.schema import AgentDecision, CaseCategory, DecisionOutcome
from src.ingestion.ingestor import DecisionIngestor, ValidationError
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch, _make_decision


def test_store_and_retrieve_decision(store):
    d = _make_decision("C001", CaseCategory.BILLING_DISPUTE)
    store.store_decision(d)
    recent = store.get_recent_decisions(CaseCategory.BILLING_DISPUTE, 10)
    assert len(recent) == 1
    assert recent[0].decision_id == d.decision_id


def test_baseline_returns_oldest(store):
    from datetime import timedelta
    base = datetime.utcnow() - timedelta(hours=2)
    decisions = make_decision_batch(CaseCategory.ROUTINE, n=20, resolve_p=0.8, error_p=0.1, escalate_p=0.1)
    store.store_decisions_batch(decisions)
    baseline = store.get_baseline_decisions(CaseCategory.ROUTINE, limit=5)
    assert len(baseline) == 5
    # Oldest first
    for i in range(len(baseline) - 1):
        assert baseline[i].timestamp <= baseline[i + 1].timestamp


def test_recent_returns_newest(store):
    decisions = make_decision_batch(CaseCategory.ROUTINE, n=20, resolve_p=0.8, error_p=0.1, escalate_p=0.1)
    store.store_decisions_batch(decisions)
    recent = store.get_recent_decisions(CaseCategory.ROUTINE, limit=5)
    assert len(recent) == 5
    # Most recent first
    for i in range(len(recent) - 1):
        assert recent[i].timestamp >= recent[i + 1].timestamp


def test_count_by_category(store):
    store.store_decisions_batch(
        make_decision_batch(CaseCategory.BILLING_DISPUTE, 10, 0.8, 0.1, 0.1)
    )
    store.store_decisions_batch(
        make_decision_batch(CaseCategory.ROUTINE, 15, 0.8, 0.1, 0.1)
    )
    counts = store.count_by_category()
    assert counts["billing_dispute"] == 10
    assert counts["routine"] == 15


def test_ingestor_rejects_invalid_confidence(config, store):
    ingestor = DecisionIngestor(store, config)
    # Create a valid decision then corrupt the confidence after construction
    # to test that the ingestor's validator catches it independently of __post_init__
    d = _make_decision("X", CaseCategory.ROUTINE)
    d.confidence = 1.5  # bypass __post_init__ via direct attr set
    with pytest.raises(ValidationError, match="confidence"):
        ingestor.ingest(d)


def test_ingestor_rejects_missing_case_id(config, store):
    ingestor = DecisionIngestor(store, config)
    d = _make_decision(case_id="", category=CaseCategory.ROUTINE)
    with pytest.raises(ValidationError, match="case_id"):
        ingestor.ingest(d)


def test_ingestor_rejects_missing_agent_version(config, store):
    ingestor = DecisionIngestor(store, config)
    d = _make_decision(agent_version="")
    with pytest.raises(ValidationError, match="agent_version"):
        ingestor.ingest(d)


def test_categorization_detects_billing(config, store):
    ingestor = DecisionIngestor(store, config)
    d = AgentDecision(
        case_id="C001",
        category=CaseCategory.UNKNOWN,
        outcome=DecisionOutcome.RESOLVED,
        confidence=0.85,
        timestamp=datetime.utcnow(),
        agent_version="v1.0",
        processing_time_ms=400.0,
        case_text="Customer is disputing a billing charge on their invoice",
    )
    result = ingestor.ingest(d)
    assert result.category == CaseCategory.BILLING_DISPUTE


def test_categorization_detects_fraud(config, store):
    ingestor = DecisionIngestor(store, config)
    d = AgentDecision(
        case_id="C002",
        category=CaseCategory.UNKNOWN,
        outcome=DecisionOutcome.ESCALATED,
        confidence=0.70,
        timestamp=datetime.utcnow(),
        agent_version="v1.0",
        processing_time_ms=600.0,
        case_text="Unauthorized transaction detected, possible fraud",
    )
    result = ingestor.ingest(d)
    assert result.category == CaseCategory.FRAUD_CLAIM


def test_categorization_fallback_to_unknown(config, store):
    ingestor = DecisionIngestor(store, config)
    d = AgentDecision(
        case_id="C003",
        category=CaseCategory.UNKNOWN,
        outcome=DecisionOutcome.RESOLVED,
        confidence=0.90,
        timestamp=datetime.utcnow(),
        agent_version="v1.0",
        processing_time_ms=300.0,
        case_text="Password reset request",
    )
    result = ingestor.ingest(d)
    assert result.category == CaseCategory.UNKNOWN


def test_batch_ingest_skips_invalid(config, store):
    ingestor = DecisionIngestor(store, config)
    good = _make_decision("G001")
    bad = AgentDecision(
        case_id="",  # invalid
        category=CaseCategory.ROUTINE,
        outcome=DecisionOutcome.RESOLVED,
        confidence=0.9,
        timestamp=datetime.utcnow(),
        agent_version="v1.0",
        processing_time_ms=500.0,
    )
    accepted, errors = ingestor.ingest_batch([good, bad])
    assert accepted == 1
    assert len(errors) == 1
    assert "case_id" in errors[0]


def test_store_is_isolated_between_categories(store):
    store.store_decisions_batch(
        make_decision_batch(CaseCategory.BILLING_DISPUTE, 5, 0.8, 0.1, 0.1)
    )
    fraud = store.get_recent_decisions(CaseCategory.FRAUD_CLAIM, 10)
    assert len(fraud) == 0


def test_alert_store_and_retrieve(store):
    from src.governance.schema import DriftAlert, AlertSeverity
    alert = DriftAlert(
        severity=AlertSeverity.CRITICAL,
        category=CaseCategory.BILLING_DISPUTE,
        message="Test alert",
        drift_score=0.85,
    )
    store.store_alert(alert)
    active = store.get_active_alerts()
    assert len(active) == 1
    assert active[0].alert_id == alert.alert_id


def test_acknowledge_alert_removes_from_active(store):
    from src.governance.schema import DriftAlert, AlertSeverity
    alert = DriftAlert(
        severity=AlertSeverity.WARNING,
        category=CaseCategory.ROUTINE,
        message="test",
        drift_score=0.45,
    )
    store.store_alert(alert)
    assert len(store.get_active_alerts()) == 1
    store.acknowledge_alert(alert.alert_id)
    assert len(store.get_active_alerts()) == 0


def test_rollback_event_store_and_retrieve(store):
    from src.governance.schema import RollbackEvent
    event = RollbackEvent(
        reason="Test rollback",
        triggered_by="test",
        category=CaseCategory.FRAUD_CLAIM,
        drift_score=0.88,
    )
    store.store_rollback_event(event)
    active = store.get_active_rollback()
    assert active is not None
    assert active.reason == "Test rollback"


def test_resolve_rollback(store):
    from src.governance.schema import RollbackEvent
    event = RollbackEvent(reason="test", triggered_by="test")
    store.store_rollback_event(event)
    store.resolve_rollback(event.event_id, "reverted to v1.0")
    active = store.get_active_rollback()
    assert active is None
