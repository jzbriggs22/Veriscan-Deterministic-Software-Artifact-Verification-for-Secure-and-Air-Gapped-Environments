"""Tests for DetectionScheduler and drift history persistence."""
from __future__ import annotations

import time
from datetime import datetime, timedelta

import pytest

from src.detection.detector import DriftDetector
from src.engine.alerts import AlertEngine
from src.engine.rollback import RollbackEngine
from src.engine.scheduler import DetectionScheduler
from src.governance.config import GovernanceConfig
from src.governance.schema import CaseCategory
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch


@pytest.fixture
def full_stack():
    config = GovernanceConfig.default()
    store = DecisionStore()
    detector = DriftDetector(store, config)
    alert_engine = AlertEngine(store, config)
    rollback_engine = RollbackEngine(store, config)
    return config, store, detector, alert_engine, rollback_engine


# ── DetectionScheduler ─────────────────────────────────────────────────────────

def test_scheduler_starts_and_stops(full_stack):
    _, store, detector, alert_engine, rollback_engine = full_stack
    scheduler = DetectionScheduler(store, detector, alert_engine, rollback_engine)
    scheduler.start(interval_seconds=60)
    assert scheduler.is_running()
    scheduler.stop(timeout=2.0)
    assert not scheduler.is_running()


def test_scheduler_start_is_idempotent(full_stack):
    _, store, detector, alert_engine, rollback_engine = full_stack
    scheduler = DetectionScheduler(store, detector, alert_engine, rollback_engine)
    scheduler.start(interval_seconds=60)
    scheduler.start(interval_seconds=60)  # second call must be no-op
    assert scheduler.is_running()
    scheduler.stop(timeout=2.0)


def test_run_now_returns_results(full_stack):
    config, store, detector, alert_engine, rollback_engine = full_stack
    now = datetime.utcnow()
    decisions = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 25,
        resolve_p=0.83, error_p=0.04, escalate_p=0.10,
        base_time=now - timedelta(days=15),
    )
    store.store_decisions_batch(decisions)

    scheduler = DetectionScheduler(store, detector, alert_engine, rollback_engine)
    results = scheduler.run_now()
    assert isinstance(results, list)


def test_run_now_persists_drift_history(full_stack):
    config, store, detector, alert_engine, rollback_engine = full_stack
    now = datetime.utcnow()
    decisions = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 25,
        resolve_p=0.83, error_p=0.04, escalate_p=0.10,
        base_time=now - timedelta(days=15),
    )
    store.store_decisions_batch(decisions)

    scheduler = DetectionScheduler(store, detector, alert_engine, rollback_engine)
    scheduler.run_now()

    history = store.get_all_drift_history(limit=50)
    assert len(history) > 0


def test_run_now_increments_cycle_count(full_stack):
    _, store, detector, alert_engine, rollback_engine = full_stack
    scheduler = DetectionScheduler(store, detector, alert_engine, rollback_engine)
    assert scheduler.cycle_count == 0
    scheduler.run_now()
    assert scheduler.cycle_count == 1
    scheduler.run_now()
    assert scheduler.cycle_count == 2


def test_on_cycle_callback_is_invoked(full_stack):
    _, store, detector, alert_engine, rollback_engine = full_stack
    received = []
    scheduler = DetectionScheduler(
        store, detector, alert_engine, rollback_engine,
        on_cycle=lambda results: received.append(results),
    )
    scheduler.run_now()
    assert len(received) == 1
    assert isinstance(received[0], list)


def test_exception_in_cycle_does_not_crash_scheduler(full_stack, monkeypatch):
    """A broken detection must not kill the scheduler loop."""
    _, store, detector, alert_engine, rollback_engine = full_stack

    def _boom(*args, **kwargs):
        raise RuntimeError("detection exploded")

    monkeypatch.setattr(detector, "run_detection", _boom)
    scheduler = DetectionScheduler(store, detector, alert_engine, rollback_engine)
    result = scheduler.run_now()  # must return [] not raise
    assert result == []
    assert scheduler.last_error is not None
    assert "detection exploded" in scheduler.last_error


def test_scheduler_dispatches_webhooks_on_alert(full_stack):
    """Webhook dispatcher is called for new alerts generated during a cycle."""
    config, store, detector, alert_engine, rollback_engine = full_stack
    now = datetime.utcnow()

    baseline = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 25,
        resolve_p=0.83, error_p=0.04, escalate_p=0.10,
        base_time=now - timedelta(days=15),
    )
    drifted = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 10,
        resolve_p=0.30, error_p=0.40, escalate_p=0.25,
        base_time=now - timedelta(hours=10),
        time_step_seconds=300,
    )
    store.store_decisions_batch(baseline)
    store.store_decisions_batch(drifted)

    dispatched_alerts = []

    class _FakeDispatcher:
        def dispatch_alert(self, alert):
            dispatched_alerts.append(alert)
            return {alert.alert_id: True}

        def dispatch_rollback(self, event):
            return {}

    scheduler = DetectionScheduler(
        store, detector, alert_engine, rollback_engine,
        dispatcher=_FakeDispatcher(),
    )
    scheduler.run_now()
    assert len(dispatched_alerts) >= 1


# ── Drift history store methods ────────────────────────────────────────────────

def test_store_and_retrieve_drift_history(full_stack):
    config, store, detector, alert_engine, rollback_engine = full_stack
    now = datetime.utcnow()
    decisions = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 20,
        resolve_p=0.80, error_p=0.05, escalate_p=0.10,
        base_time=now - timedelta(days=15),
    )
    recent = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 8,
        resolve_p=0.40, error_p=0.30, escalate_p=0.25,
        base_time=now - timedelta(hours=10),
        time_step_seconds=300,
    )
    store.store_decisions_batch(decisions)
    store.store_decisions_batch(recent)

    results = detector.run_detection()
    store.store_drift_results_batch(results)

    history = store.get_drift_history(CaseCategory.FRAUD_CLAIM, limit=10)
    assert len(history) >= 1
    point = history[0]
    assert point["category"] == "fraud_claim"
    assert isinstance(point["drift_score"], float)
    assert isinstance(point["timestamp"], datetime)


def test_drift_history_only_for_requested_category(full_stack):
    _, store, detector, alert_engine, rollback_engine = full_stack
    now = datetime.utcnow()
    for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM]:
        d = make_decision_batch(cat, 25, 0.83, 0.04, 0.10,
                                base_time=now - timedelta(days=15))
        store.store_decisions_batch(d)

    results = detector.run_detection()
    store.store_drift_results_batch(results)

    billing_history = store.get_drift_history(CaseCategory.BILLING_DISPUTE)
    assert all(p["category"] == "billing_dispute" for p in billing_history)


def test_drift_history_since_filter(full_stack):
    _, store, detector, alert_engine, rollback_engine = full_stack
    now = datetime.utcnow()
    decisions = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 25, 0.83, 0.04, 0.10,
        base_time=now - timedelta(days=15),
    )
    store.store_decisions_batch(decisions)

    results = detector.run_detection()
    store.store_drift_results_batch(results)

    # Ask for history from 1 hour in the future — should be empty
    future = now + timedelta(hours=1)
    history = store.get_drift_history(CaseCategory.BILLING_DISPUTE, since=future)
    assert history == []


def test_get_latest_drift_result(full_stack):
    _, store, detector, alert_engine, rollback_engine = full_stack
    now = datetime.utcnow()
    decisions = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 25, 0.83, 0.04, 0.10,
        base_time=now - timedelta(days=15),
    )
    store.store_decisions_batch(decisions)

    results = detector.run_detection()
    store.store_drift_results_batch(results)

    latest = store.get_latest_drift_result(CaseCategory.BILLING_DISPUTE)
    assert latest is not None
    assert latest["category"] == "billing_dispute"


def test_get_latest_drift_result_none_when_empty(store):
    result = store.get_latest_drift_result(CaseCategory.FRAUD_CLAIM)
    assert result is None


# ── API: history endpoints ─────────────────────────────────────────────────────

def test_api_category_history_empty(full_stack):
    from fastapi.testclient import TestClient
    from src.api.app import app, configure
    config, store, *_ = full_stack
    configure(config, store)
    tc = TestClient(app)

    resp = tc.get("/governance/categories/billing_dispute/history")
    assert resp.status_code == 200
    body = resp.json()
    assert body["category"] == "billing_dispute"
    assert body["points"] == []
    assert body["trend"] == "unknown"


def test_api_category_history_invalid_category(full_stack):
    from fastapi.testclient import TestClient
    from src.api.app import app, configure
    config, store, *_ = full_stack
    configure(config, store)
    tc = TestClient(app)

    resp = tc.get("/governance/categories/nonexistent_cat/history")
    assert resp.status_code == 404


def test_api_all_drift_history(full_stack):
    from fastapi.testclient import TestClient
    from src.api.app import app, configure
    config, store, detector, alert_engine, rollback_engine = full_stack
    configure(config, store)
    tc = TestClient(app)

    now = datetime.utcnow()
    decisions = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 25, 0.83, 0.04, 0.10,
        base_time=now - timedelta(days=15),
    )
    store.store_decisions_batch(decisions)

    # Trigger a detection cycle to populate history
    tc.post("/scheduler/run-now")

    resp = tc.get("/governance/history")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_run_now_endpoint(full_stack):
    from fastapi.testclient import TestClient
    from src.api.app import app, configure
    config, store, *_ = full_stack
    configure(config, store)
    tc = TestClient(app)

    resp = tc.post("/scheduler/run-now")
    assert resp.status_code == 200
    body = resp.json()
    assert "categories_checked" in body
    assert "new_alerts" in body
    assert "rollback_triggered" in body
    assert "drift_scores" in body


def test_api_scheduler_status_no_scheduler(full_stack):
    from fastapi.testclient import TestClient
    from src.api.app import app, configure
    config, store, *_ = full_stack
    configure(config, store, scheduler=None)
    tc = TestClient(app)

    resp = tc.get("/scheduler/status")
    assert resp.status_code == 200
    assert resp.json()["running"] is False


def test_api_scheduler_status_with_scheduler(full_stack):
    from fastapi.testclient import TestClient
    from src.api.app import app, configure
    config, store, detector, alert_engine, rollback_engine = full_stack
    scheduler = DetectionScheduler(store, detector, alert_engine, rollback_engine)
    scheduler.start(interval_seconds=300)
    configure(config, store, scheduler=scheduler)
    tc = TestClient(app)

    try:
        resp = tc.get("/scheduler/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["running"] is True
        assert body["interval_seconds"] == 300.0
    finally:
        scheduler.stop(timeout=2.0)
