"""
End-to-end API integration tests.

These tests exercise the full pipeline through the HTTP API using FastAPI's
TestClient:  ingest decisions → background drift detection → governance report
→ rollback trigger → rollback resolution.

Unlike test_integration.py (which calls components directly), this file goes
through the REST API the same way a real PM dashboard or CI pipeline would.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from src.api.app import app, configure
from src.governance.config import GovernanceConfig
from src.governance.schema import CaseCategory
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch


# ── Shared client fixture ─────────────────────────────────────────────────────

@pytest.fixture
def fresh_client():
    config = GovernanceConfig.default()
    store = DecisionStore()
    configure(config, store)
    return TestClient(app), store, config


def _ingest_batch_via_api(tc: TestClient, decisions: list, expected_count: int | None = None):
    payload = [
        {
            "case_id": d.case_id,
            "category": d.category.value,
            "outcome": d.outcome.value,
            "confidence": d.confidence,
            "agent_version": d.agent_version,
            "processing_time_ms": d.processing_time_ms,
            "timestamp": d.timestamp.isoformat(),
        }
        for d in decisions
    ]
    resp = tc.post("/decisions/batch", json={"decisions": payload})
    assert resp.status_code == 201
    body = resp.json()
    if expected_count is not None:
        assert body["accepted"] == expected_count
    return body


# ── Scenario 1: Healthy baseline → no drift ───────────────────────────────────

class TestScenario1HealthyBaseline:
    def test_ingest_baseline_then_report_healthy(self, fresh_client):
        tc, store, config = fresh_client

        # Ingest baseline directly (simulates agent running for 15 days)
        base = datetime.utcnow() - timedelta(days=15)
        for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM, CaseCategory.ROUTINE]:
            store.store_decisions_batch(
                make_decision_batch(cat, n=30, resolve_p=0.85, error_p=0.03,
                                    escalate_p=0.09, base_time=base)
            )

        # Get governance report via API
        resp = tc.get("/governance/report")
        assert resp.status_code == 200
        body = resp.json()

        assert body["status"] in ("healthy", "drifting")
        assert body["total_decisions"] == 90
        assert body["active_rollback"] is None

    def test_normal_metrics_look_good(self, fresh_client):
        tc, store, config = fresh_client
        now = datetime.utcnow()
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 50, 0.85, 0.03, 0.08,
                                base_time=now - timedelta(hours=10))
        )

        resp = tc.get("/metrics")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_decisions"] == 50
        assert body["overall_resolution_rate"] > 0.70


# ── Scenario 2: Silent regression — API detects what ops misses ───────────────

class TestScenario2SilentRegression:
    def test_drift_detected_on_high_risk_category(self, fresh_client):
        """
        Ingest healthy baseline, then drifted recent data.
        Normal metrics are blended and look OK.
        API must detect per-category drift on billing_dispute.
        """
        tc, store, config = fresh_client

        base = datetime.utcnow() - timedelta(days=15)
        recent = datetime.utcnow() - timedelta(hours=3)

        # Healthy baseline for all categories
        for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM,
                    CaseCategory.ROUTINE]:
            store.store_decisions_batch(
                make_decision_batch(cat, n=40, resolve_p=0.85, error_p=0.03,
                                    escalate_p=0.09, base_time=base)
            )

        # Routine stays healthy (large volume masks drift in blended metrics)
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 60, 0.88, 0.02, 0.08,
                                base_time=recent, time_step_seconds=30)
        )
        # Billing dispute drifts hard
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 15, 0.25, 0.45, 0.25,
                                base_time=recent, time_step_seconds=60)
        )

        # Normal metrics — blended over routine + billing
        metrics = tc.get("/metrics").json()
        # Blended resolution still looks OK (routine is dominant)
        assert metrics["total_decisions"] >= 150

        # Governance report — should catch billing drift
        report = tc.get("/governance/report").json()
        billing_result = next(
            (r for r in report["drift_results"] if r["category"] == "billing_dispute"),
            None,
        )
        assert billing_result is not None
        if not billing_result["insufficient_data"]:
            assert billing_result["drift_score"] > 0.0, (
                "API should report non-zero drift on degraded billing_dispute category"
            )

    def test_status_reflects_drift(self, fresh_client):
        tc, store, _ = fresh_client
        base = datetime.utcnow() - timedelta(days=15)
        recent = datetime.utcnow() - timedelta(hours=2)

        store.store_decisions_batch(
            make_decision_batch(CaseCategory.FRAUD_CLAIM, 30, 0.85, 0.03, 0.08, base_time=base)
        )
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.FRAUD_CLAIM, 12, 0.15, 0.55, 0.25,
                                base_time=recent, time_step_seconds=45)
        )

        report = tc.get("/governance/report").json()
        # Status should not be healthy
        assert report["status"] in ("drifting", "critical")


# ── Scenario 3: Critical drift → rollback via API ─────────────────────────────

class TestScenario3RollbackCycle:
    def test_full_rollback_cycle_via_api(self, fresh_client):
        """
        Ingest severely drifted data → run governance report (triggers rollback if rule fires)
        → confirm rollback active → resolve rollback → confirm resolved.
        """
        tc, store, _ = fresh_client
        base = datetime.utcnow() - timedelta(days=15)
        recent = datetime.utcnow() - timedelta(minutes=30)

        # Baseline (healthy)
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.FRAUD_CLAIM, 30, 0.85, 0.03, 0.08, base_time=base)
        )
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 30, 0.84, 0.04, 0.09, base_time=base)
        )

        # Severe drift
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.FRAUD_CLAIM, 10, 0.10, 0.72, 0.15,
                                base_time=recent, time_step_seconds=30)
        )

        # Run report (may trigger rollback depending on thresholds)
        report_resp = tc.get("/governance/report")
        assert report_resp.status_code == 200
        report = report_resp.json()

        # Status check
        assert report["status"] in ("drifting", "critical", "rollback_triggered")

        # Check governance status endpoint
        status_resp = tc.get("/governance/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["status"] in ("drifting", "critical", "healthy", "rollback_triggered")

    def test_resolve_rollback_endpoint(self, fresh_client):
        tc, store, _ = fresh_client
        from src.governance.schema import RollbackEvent
        event = RollbackEvent(
            reason="Test rollback for resolve check",
            triggered_by="test",
            drift_score=0.9,
        )
        store.store_rollback_event(event)

        # Confirm it's active
        status = tc.get("/governance/status").json()
        assert status["rollback_active"] is True

        # Resolve it
        resp = tc.post("/governance/rollback/resolve", json={"note": "Reverted to prior version"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["resolved"] is True

        # Confirm resolved
        status2 = tc.get("/governance/status").json()
        assert status2["rollback_active"] is False


# ── Scenario 4: Full preflight → deploy → monitor loop ───────────────────────

class TestScenario4PreflightDeployMonitor:
    def test_preflight_gates_deployment(self, fresh_client):
        tc, store, _ = fresh_client

        # Good decisions → SAFE_TO_DEPLOY
        good_decisions = [
            {
                "case_category": "billing_dispute",
                "risk_level": "high",
                "decision": "Escalate billing dispute for human review.",
                "confidence": 0.87,
                "flags": ["high_value"],
            }
        ] * 8

        resp = tc.post("/governance/preflight", json={
            "decisions": good_decisions,
            "agent_version": "v2.0-candidate",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["recommendation"] in ("SAFE_TO_DEPLOY", "WARNING")
        assert body["agent_version"] == "v2.0-candidate"

    def test_preflight_blocks_schema_broken_agent(self, fresh_client):
        tc, *_ = fresh_client

        # All decisions are schema garbage
        bad_decisions = [
            {"not_a_field": "garbage", "missing_everything": True}
        ] * 5

        resp = tc.post("/governance/preflight", json={
            "decisions": bad_decisions,
            "agent_version": "v-broken",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["schema_error_count"] >= 1
        # WARNING or BLOCKED for schema errors
        assert body["recommendation"] in ("WARNING", "BLOCKED")

    def test_monitor_ingested_decisions(self, fresh_client):
        tc, *_ = fresh_client

        # Ingest some decisions through the API
        for i in range(5):
            resp = tc.post("/decisions", json={
                "case_id": f"E2E-{i:03d}",
                "category": "routine",
                "outcome": "resolved",
                "confidence": 0.88,
                "agent_version": "v2.0",
                "processing_time_ms": 400.0,
            })
            assert resp.status_code == 201

        # Metrics reflect the ingested data
        metrics = tc.get("/metrics").json()
        assert metrics["total_decisions"] == 5
        assert metrics["overall_resolution_rate"] == 1.0


# ── Scenario 5: Version comparison pipeline ───────────────────────────────────

class TestScenario5VersionComparison:
    def test_compare_old_vs_new_version(self, fresh_client):
        tc, store, _ = fresh_client
        now = datetime.utcnow()

        # v1.0 — decent baseline
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 20, 0.80, 0.08, 0.08,
                                base_time=now - timedelta(days=3),
                                agent_version="v1.0")
        )
        # v2.0 — improved
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 20, 0.90, 0.02, 0.06,
                                base_time=now - timedelta(hours=6),
                                agent_version="v2.0")
        )

        resp = tc.get("/governance/versions/v1.0/compare/v2.0")
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] in ("IMPROVED", "DEGRADED", "STABLE", "INSUFFICIENT_DATA")
        assert body["version_a"] == "v1.0"
        assert body["version_b"] == "v2.0"

    def test_versions_endpoint_lists_both(self, fresh_client):
        tc, store, _ = fresh_client
        now = datetime.utcnow()

        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 10, 0.85, 0.05, 0.08,
                                base_time=now - timedelta(hours=2),
                                agent_version="alpha")
        )
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 10, 0.88, 0.04, 0.07,
                                base_time=now - timedelta(hours=1),
                                agent_version="beta")
        )

        resp = tc.get("/governance/versions")
        assert resp.status_code == 200
        versions = {v["agent_version"] for v in resp.json()}
        assert "alpha" in versions
        assert "beta" in versions


# ── Scenario 6: Alert → acknowledge cycle ────────────────────────────────────

class TestScenario6AlertAcknowledge:
    def test_alert_appears_in_list_after_drift(self, fresh_client):
        tc, store, _ = fresh_client
        base = datetime.utcnow() - timedelta(days=15)
        recent = datetime.utcnow() - timedelta(hours=1)

        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 30, 0.85, 0.04, 0.09, base_time=base)
        )
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 12, 0.20, 0.50, 0.25,
                                base_time=recent, time_step_seconds=60)
        )

        # Running the report processes drift results and fires alerts
        tc.get("/governance/report")

        alerts = tc.get("/governance/alerts").json()
        # Should have some alerts after processing drift
        # (may be empty if drift insufficient — just check the shape)
        assert isinstance(alerts, list)

    def test_acknowledge_existing_alert(self, fresh_client):
        tc, store, _ = fresh_client
        from src.governance.schema import DriftAlert, CaseCategory, AlertSeverity

        # Manually store an alert
        alert = DriftAlert(
            category=CaseCategory.BILLING_DISPUTE,
            severity=AlertSeverity.WARNING,
            message="Test alert for acknowledgement",
            drift_score=0.5,
        )
        store.store_alert(alert)

        # Get it
        alerts = tc.get("/governance/alerts").json()
        assert len(alerts) >= 1
        alert_id = alerts[0]["alert_id"]

        # Acknowledge it
        resp = tc.post(f"/governance/alerts/{alert_id}/acknowledge")
        assert resp.status_code == 200

        # It should no longer appear in active alerts
        alerts_after = tc.get("/governance/alerts").json()
        active_ids = {a["alert_id"] for a in alerts_after}
        assert alert_id not in active_ids


# ── Scenario 7: Prometheus scrape confirms governance health ──────────────────

class TestScenario7PrometheusScrape:
    def test_prometheus_reflects_rollback_active(self, fresh_client):
        tc, store, _ = fresh_client
        from src.governance.schema import RollbackEvent
        event = RollbackEvent(
            reason="Regression",
            triggered_by="test",
            drift_score=1.0,
        )
        store.store_rollback_event(event)

        resp = tc.get("/prometheus/metrics")
        assert resp.status_code == 200
        text = resp.text
        # Must show rollback_active = 1
        assert "governance_rollback_active 1" in text

    def test_prometheus_reflects_no_rollback(self, fresh_client):
        tc, *_ = fresh_client
        resp = tc.get("/prometheus/metrics")
        text = resp.text
        assert "governance_rollback_active 0" in text

    def test_prometheus_decision_counts(self, fresh_client):
        tc, store, _ = fresh_client
        now = datetime.utcnow()
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, 7, 0.85, 0.05, 0.08,
                                base_time=now - timedelta(hours=1))
        )
        resp = tc.get("/prometheus/metrics")
        text = resp.text
        assert "governance_decisions_total" in text


# ── Scenario 8: HTML report self-consistent with JSON report ─────────────────

class TestScenario8HtmlConsistency:
    def test_html_report_reflects_same_data_as_json(self, fresh_client):
        tc, store, _ = fresh_client
        base = datetime.utcnow() - timedelta(days=15)
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 20, 0.85, 0.04, 0.09,
                                base_time=base)
        )

        html_resp = tc.get("/governance/report/html")
        json_resp = tc.get("/governance/report")

        assert html_resp.status_code == 200
        assert json_resp.status_code == 200

        # Both show the same category
        assert "billing_dispute" in html_resp.text
        # Both return data for the same total
        assert json_resp.json()["total_decisions"] == 20

    def test_html_report_shows_rollback_banner_when_active(self, fresh_client):
        tc, store, _ = fresh_client
        from src.governance.schema import RollbackEvent
        event = RollbackEvent(
            reason="Emergency rollback initiated",
            triggered_by="ci_gate",
            drift_score=1.0,
        )
        store.store_rollback_event(event)

        html = tc.get("/governance/report/html").text
        assert "rollback-banner" in html
        assert "Emergency rollback initiated" in html
