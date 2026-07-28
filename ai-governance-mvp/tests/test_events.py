"""Tests for GovernanceEventBroker (SSE), Prometheus metrics, and case drill-down."""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta

import pytest

from src.engine.events import GovernanceEventBroker, get_broker
from src.governance.config import GovernanceConfig
from src.governance.schema import CaseCategory
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch


# ── GovernanceEventBroker ──────────────────────────────────────────────────────

class TestGovernanceEventBroker:

    def test_initial_state(self):
        broker = GovernanceEventBroker()
        assert broker.subscriber_count == 0
        assert broker.published_total == 0

    def test_publish_with_no_subscribers_does_not_raise(self):
        broker = GovernanceEventBroker()
        broker.publish("test_event", {"key": "value"})
        assert broker.published_total == 1

    def test_publish_increments_counter(self):
        broker = GovernanceEventBroker()
        broker.publish("event_a", {})
        broker.publish("event_b", {})
        broker.publish("event_c", {})
        assert broker.published_total == 3

    @pytest.mark.asyncio
    async def test_subscribe_receives_published_event(self):
        broker = GovernanceEventBroker()

        received: list[str] = []

        async def _consumer():
            async for frame in broker.subscribe(heartbeat_seconds=1.0):
                received.append(frame)
                break  # stop after first event

        # Start consumer
        task = asyncio.create_task(_consumer())
        await asyncio.sleep(0.05)  # let consumer register

        broker.publish("drift_detected", {"category": "billing_dispute", "drift_score": 0.42})
        await asyncio.wait_for(task, timeout=2.0)

        assert len(received) == 1
        assert "drift_detected" in received[0]
        assert "billing_dispute" in received[0]

    @pytest.mark.asyncio
    async def test_subscribe_frame_is_valid_sse(self):
        broker = GovernanceEventBroker()

        received: list[str] = []

        async def _consumer():
            async for frame in broker.subscribe(heartbeat_seconds=1.0):
                received.append(frame)
                break

        task = asyncio.create_task(_consumer())
        await asyncio.sleep(0.05)

        broker.publish("alert_fired", {"alert_id": "abc", "severity": "critical"})
        await asyncio.wait_for(task, timeout=2.0)

        frame = received[0]
        assert frame.startswith("event: alert_fired\n")
        assert "data: " in frame
        assert frame.endswith("\n\n")

        # data line must be valid JSON
        data_line = [l for l in frame.split("\n") if l.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: "):])
        assert payload["event"] == "alert_fired"
        assert "timestamp" in payload

    @pytest.mark.asyncio
    async def test_subscriber_count_increments_and_decrements(self):
        broker = GovernanceEventBroker()
        assert broker.subscriber_count == 0

        ready = asyncio.Event()
        done = asyncio.Event()

        async def _consumer():
            async for _ in broker.subscribe(heartbeat_seconds=0.1):
                ready.set()
                await done.wait()
                break

        task = asyncio.create_task(_consumer())
        broker.publish("ping", {})  # wake consumer
        await asyncio.wait_for(ready.wait(), timeout=2.0)
        assert broker.subscriber_count == 1

        done.set()
        await asyncio.wait_for(task, timeout=2.0)
        assert broker.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_multiple_subscribers_each_receive_event(self):
        broker = GovernanceEventBroker()
        results: list[list[str]] = [[], []]

        async def _consumer(idx: int):
            async for frame in broker.subscribe(heartbeat_seconds=1.0):
                results[idx].append(frame)
                break

        t1 = asyncio.create_task(_consumer(0))
        t2 = asyncio.create_task(_consumer(1))
        await asyncio.sleep(0.05)

        broker.publish("rollback_triggered", {"event_id": "R1"})
        await asyncio.gather(
            asyncio.wait_for(t1, timeout=2.0),
            asyncio.wait_for(t2, timeout=2.0),
        )

        assert len(results[0]) == 1
        assert len(results[1]) == 1
        assert results[0][0] == results[1][0]  # same event, same frame

    @pytest.mark.asyncio
    async def test_heartbeat_is_comment_format(self):
        broker = GovernanceEventBroker()
        received: list[str] = []

        async def _consumer():
            async for frame in broker.subscribe(heartbeat_seconds=0.05):
                received.append(frame)
                if len(received) >= 1:
                    break

        task = asyncio.create_task(_consumer())
        await asyncio.wait_for(task, timeout=2.0)

        assert len(received) >= 1
        # heartbeat is a comment: starts with ":"
        heartbeat = received[0]
        assert heartbeat.startswith(": keepalive")

    @pytest.mark.asyncio
    async def test_publish_includes_timestamp(self):
        broker = GovernanceEventBroker()
        received: list[str] = []

        async def _consumer():
            async for frame in broker.subscribe(heartbeat_seconds=1.0):
                received.append(frame)
                break

        task = asyncio.create_task(_consumer())
        await asyncio.sleep(0.05)

        broker.publish("cycle_complete", {"cycle": 1})
        await asyncio.wait_for(task, timeout=2.0)

        data_line = [l for l in received[0].split("\n") if l.startswith("data: ")][0]
        payload = json.loads(data_line[len("data: "):])
        assert "timestamp" in payload
        # Should be parseable as ISO datetime
        datetime.fromisoformat(payload["timestamp"])

    def test_get_broker_returns_singleton(self):
        b1 = get_broker()
        b2 = get_broker()
        assert b1 is b2

    @pytest.mark.asyncio
    async def test_publish_with_non_serializable_default_str(self):
        """CaseCategory enum values (non-JSON-native) should not raise."""
        broker = GovernanceEventBroker()
        received: list[str] = []

        async def _consumer():
            async for frame in broker.subscribe(heartbeat_seconds=1.0):
                received.append(frame)
                break

        task = asyncio.create_task(_consumer())
        await asyncio.sleep(0.05)

        broker.publish("drift_detected", {"category": CaseCategory.BILLING_DISPUTE})
        await asyncio.wait_for(task, timeout=2.0)
        assert len(received) == 1


# ── Scheduler SSE integration ──────────────────────────────────────────────────

class TestSchedulerSSEIntegration:

    def test_scheduler_publishes_cycle_complete_on_run_now(self):
        from src.detection.detector import DriftDetector
        from src.engine.alerts import AlertEngine
        from src.engine.rollback import RollbackEngine
        from src.engine.scheduler import DetectionScheduler

        config = GovernanceConfig.default()
        store = DecisionStore()
        broker = GovernanceEventBroker()

        detector = DriftDetector(store, config)
        alert_engine = AlertEngine(store, config)
        rollback_engine = RollbackEngine(store, config)
        scheduler = DetectionScheduler(
            store, detector, alert_engine, rollback_engine,
            event_broker=broker,
        )
        scheduler.run_now()
        assert broker.published_total >= 1  # at least cycle_complete

    def test_scheduler_publishes_alert_and_rollback_events(self):
        from src.detection.detector import DriftDetector
        from src.engine.alerts import AlertEngine
        from src.engine.rollback import RollbackEngine
        from src.engine.scheduler import DetectionScheduler

        config = GovernanceConfig.default()
        store = DecisionStore()
        broker = GovernanceEventBroker()
        now = datetime.utcnow()

        baseline = make_decision_batch(
            CaseCategory.BILLING_DISPUTE, 80,
            resolve_p=0.83, error_p=0.04, escalate_p=0.10,
            base_time=now - timedelta(days=15),
        )
        drifted = make_decision_batch(
            CaseCategory.BILLING_DISPUTE, 40,
            resolve_p=0.20, error_p=0.50, escalate_p=0.25,
            base_time=now - timedelta(hours=12),
            time_step_seconds=120,
        )
        store.store_decisions_batch(baseline)
        store.store_decisions_batch(drifted)

        detector = DriftDetector(store, config)
        alert_engine = AlertEngine(store, config)
        rollback_engine = RollbackEngine(store, config)
        scheduler = DetectionScheduler(
            store, detector, alert_engine, rollback_engine,
            event_broker=broker,
        )
        scheduler.run_now()
        # With high drift, should have drift_detected + alert_fired events
        assert broker.published_total > 1

    def test_scheduler_without_broker_still_works(self):
        from src.detection.detector import DriftDetector
        from src.engine.alerts import AlertEngine
        from src.engine.rollback import RollbackEngine
        from src.engine.scheduler import DetectionScheduler

        config = GovernanceConfig.default()
        store = DecisionStore()
        detector = DriftDetector(store, config)
        alert_engine = AlertEngine(store, config)
        rollback_engine = RollbackEngine(store, config)
        scheduler = DetectionScheduler(store, detector, alert_engine, rollback_engine)
        result = scheduler.run_now()  # must not raise
        assert isinstance(result, list)


# ── API: Prometheus metrics ────────────────────────────────────────────────────

class TestPrometheusMetrics:

    @pytest.fixture
    def client_with_data(self):
        from fastapi.testclient import TestClient
        from src.api.app import app, configure

        config = GovernanceConfig.default()
        store = DecisionStore()
        configure(config, store)

        now = datetime.utcnow()
        for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM]:
            baseline = make_decision_batch(
                cat, 50, resolve_p=0.83, error_p=0.04, escalate_p=0.10,
                base_time=now - timedelta(days=15),
            )
            recent = make_decision_batch(
                cat, 20, resolve_p=0.83, error_p=0.04, escalate_p=0.10,
                base_time=now - timedelta(hours=12),
                time_step_seconds=120,
            )
            store.store_decisions_batch(baseline)
            store.store_decisions_batch(recent)

        return TestClient(app)

    def test_prometheus_returns_200(self, client_with_data):
        resp = client_with_data.get("/prometheus/metrics")
        assert resp.status_code == 200

    def test_prometheus_content_type_is_plain_text(self, client_with_data):
        resp = client_with_data.get("/prometheus/metrics")
        assert "text/plain" in resp.headers["content-type"]

    def test_prometheus_contains_help_lines(self, client_with_data):
        resp = client_with_data.get("/prometheus/metrics")
        body = resp.text
        assert "# HELP governance_drift_score" in body
        assert "# TYPE governance_drift_score gauge" in body

    def test_prometheus_contains_drift_score_metrics(self, client_with_data):
        resp = client_with_data.get("/prometheus/metrics")
        body = resp.text
        assert "governance_drift_score{" in body

    def test_prometheus_contains_decisions_total(self, client_with_data):
        resp = client_with_data.get("/prometheus/metrics")
        body = resp.text
        assert "governance_decisions_total{" in body

    def test_prometheus_contains_alerts_active(self, client_with_data):
        resp = client_with_data.get("/prometheus/metrics")
        body = resp.text
        assert "governance_alerts_active" in body

    def test_prometheus_contains_rollback_active(self, client_with_data):
        resp = client_with_data.get("/prometheus/metrics")
        body = resp.text
        assert "governance_rollback_active" in body

    def test_prometheus_rollback_active_is_zero_when_no_rollback(self, client_with_data):
        resp = client_with_data.get("/prometheus/metrics")
        assert "governance_rollback_active 0" in resp.text

    def test_prometheus_metric_values_are_floats(self, client_with_data):
        resp = client_with_data.get("/prometheus/metrics")
        for line in resp.text.splitlines():
            if line.startswith("governance_") and not line.startswith("# ") and "{" in line:
                # e.g. governance_drift_score{category="billing_dispute"} 0.123456
                parts = line.rsplit("} ", 1)
                assert len(parts) == 2, f"Cannot parse metric line: {line!r}"
                float(parts[1])  # must not raise

    def test_prometheus_empty_store_still_returns_200(self):
        from fastapi.testclient import TestClient
        from src.api.app import app, configure
        config = GovernanceConfig.default()
        store = DecisionStore()
        configure(config, store)
        tc = TestClient(app)
        resp = tc.get("/prometheus/metrics")
        assert resp.status_code == 200


# ── API: Category drill-down ───────────────────────────────────────────────────

class TestCategoryDrillDown:

    @pytest.fixture
    def client_with_decisions(self):
        from fastapi.testclient import TestClient
        from src.api.app import app, configure

        config = GovernanceConfig.default()
        store = DecisionStore()
        configure(config, store)

        now = datetime.utcnow()
        decisions = make_decision_batch(
            CaseCategory.BILLING_DISPUTE, 20,
            resolve_p=0.50, error_p=0.25, escalate_p=0.20,
            base_time=now - timedelta(hours=12),
            time_step_seconds=120,
        )
        store.store_decisions_batch(decisions)
        return TestClient(app), store

    def test_drill_down_returns_200(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions")
        assert resp.status_code == 200

    def test_drill_down_returns_correct_category(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions")
        body = resp.json()
        assert body["category"] == "billing_dispute"

    def test_drill_down_total_matches_decisions_list(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions")
        body = resp.json()
        assert body["total"] == len(body["decisions"])

    def test_drill_down_decisions_in_window(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions?hours=24")
        body = resp.json()
        assert body["hours"] == 24
        assert body["total"] > 0

    def test_drill_down_outcome_filter_error(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions?outcome=error")
        body = resp.json()
        for d in body["decisions"]:
            assert d["outcome"] == "error"

    def test_drill_down_outcome_filter_resolved(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions?outcome=resolved")
        body = resp.json()
        for d in body["decisions"]:
            assert d["outcome"] == "resolved"

    def test_drill_down_invalid_category_returns_404(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/nonexistent/decisions")
        assert resp.status_code == 404

    def test_drill_down_invalid_outcome_returns_422(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions?outcome=invalid")
        assert resp.status_code == 422

    def test_drill_down_has_outcome_counts(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions")
        body = resp.json()
        assert "outcome_counts" in body
        total_from_counts = sum(body["outcome_counts"].values())
        assert total_from_counts == body["total"]

    def test_drill_down_has_rate_fields(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions")
        body = resp.json()
        assert "resolution_rate" in body
        assert "error_rate" in body
        assert "escalation_rate" in body
        assert "mean_confidence" in body

    def test_drill_down_rates_sum_leq_one(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions")
        body = resp.json()
        rate_sum = body["resolution_rate"] + body["error_rate"] + body["escalation_rate"]
        assert rate_sum <= 1.0 + 1e-6  # floating point tolerance

    def test_drill_down_empty_window_returns_zero_total(self, client_with_decisions):
        tc, _ = client_with_decisions
        # hours=1 should capture nothing since data starts 12 hours ago
        resp = tc.get("/governance/categories/billing_dispute/decisions?hours=1")
        body = resp.json()
        assert body["total"] == 0
        assert body["decisions"] == []

    def test_drill_down_decision_fields_present(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions")
        body = resp.json()
        if body["decisions"]:
            d = body["decisions"][0]
            assert "decision_id" in d
            assert "case_id" in d
            assert "outcome" in d
            assert "confidence" in d
            assert "timestamp" in d
            assert "agent_version" in d

    def test_drill_down_limit_respected(self, client_with_decisions):
        tc, _ = client_with_decisions
        resp = tc.get("/governance/categories/billing_dispute/decisions?limit=5")
        body = resp.json()
        assert len(body["decisions"]) <= 5

    def test_broker_status_endpoint(self):
        from fastapi.testclient import TestClient
        from src.api.app import app, configure
        config = GovernanceConfig.default()
        store = DecisionStore()
        configure(config, store)
        tc = TestClient(app)
        resp = tc.get("/governance/events/status")
        assert resp.status_code == 200
        body = resp.json()
        assert "subscriber_count" in body
        assert "published_total" in body
        assert body["subscriber_count"] >= 0


# ── Store drill-down method ────────────────────────────────────────────────────

class TestStoreDrillDown:

    def test_returns_decisions_in_window(self, store):
        now = datetime.utcnow()
        decisions = make_decision_batch(
            CaseCategory.BILLING_DISPUTE, 10,
            resolve_p=0.7, error_p=0.2, escalate_p=0.1,
            base_time=now - timedelta(hours=12),
            time_step_seconds=120,
        )
        store.store_decisions_batch(decisions)
        result = store.get_decisions_for_drill_down(CaseCategory.BILLING_DISPUTE, hours=24)
        assert len(result) == 10

    def test_excludes_decisions_outside_window(self, store):
        now = datetime.utcnow()
        old = make_decision_batch(
            CaseCategory.BILLING_DISPUTE, 5,
            resolve_p=0.8, error_p=0.1, escalate_p=0.1,
            base_time=now - timedelta(hours=48),
        )
        recent = make_decision_batch(
            CaseCategory.BILLING_DISPUTE, 5,
            resolve_p=0.8, error_p=0.1, escalate_p=0.1,
            base_time=now - timedelta(hours=12),
        )
        store.store_decisions_batch(old)
        store.store_decisions_batch(recent)
        result = store.get_decisions_for_drill_down(CaseCategory.BILLING_DISPUTE, hours=24)
        assert len(result) == 5

    def test_outcome_filter_works(self, store):
        now = datetime.utcnow()
        decisions = make_decision_batch(
            CaseCategory.FRAUD_CLAIM, 20,
            resolve_p=0.5, error_p=0.3, escalate_p=0.2,
            base_time=now - timedelta(hours=12),
        )
        store.store_decisions_batch(decisions)
        errors = store.get_decisions_for_drill_down(
            CaseCategory.FRAUD_CLAIM, hours=24, outcome="error"
        )
        assert all(d.outcome.value == "error" for d in errors)

    def test_limit_is_respected(self, store):
        now = datetime.utcnow()
        decisions = make_decision_batch(
            CaseCategory.ROUTINE, 30,
            resolve_p=0.9, error_p=0.05, escalate_p=0.05,
            base_time=now - timedelta(hours=12),
        )
        store.store_decisions_batch(decisions)
        result = store.get_decisions_for_drill_down(CaseCategory.ROUTINE, hours=24, limit=10)
        assert len(result) <= 10

    def test_returns_most_recent_first(self, store):
        now = datetime.utcnow()
        decisions = make_decision_batch(
            CaseCategory.ROUTINE, 10,
            resolve_p=0.9, error_p=0.05, escalate_p=0.05,
            base_time=now - timedelta(hours=12),
            time_step_seconds=600,
        )
        store.store_decisions_batch(decisions)
        result = store.get_decisions_for_drill_down(CaseCategory.ROUTINE, hours=24)
        for i in range(len(result) - 1):
            assert result[i].timestamp >= result[i + 1].timestamp
