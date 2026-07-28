"""
Extended API tests covering newer endpoints:
  - GET /governance/report/html
  - GET /prometheus/metrics
  - POST /governance/preflight
  - GET /governance/versions
  - GET /governance/versions/{v}/decisions
  - GET /governance/versions/{v1}/compare/{v2}
  - GET /governance/events/status
  - GET /governance/categories/{cat}/decisions
  - GET /governance/categories/{cat}/history
  - GET /scheduler/status
  - POST /scheduler/run-now
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from src.api.app import app, configure
from src.governance.config import GovernanceConfig
from src.governance.schema import CaseCategory
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch


@pytest.fixture
def client():
    config = GovernanceConfig.default()
    store = DecisionStore()
    configure(config, store)
    return TestClient(app), store, config


@pytest.fixture
def populated_client():
    """Client with healthy baseline + recent data for two versions."""
    config = GovernanceConfig.default()
    store = DecisionStore()
    configure(config, store)
    tc = TestClient(app)

    now = datetime.utcnow()
    base = now - timedelta(days=15)
    recent = now - timedelta(hours=12)

    for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM, CaseCategory.ROUTINE]:
        store.store_decisions_batch(
            make_decision_batch(cat, n=30, resolve_p=0.83, error_p=0.04, escalate_p=0.10,
                                base_time=base, agent_version="v1.0")
        )
        store.store_decisions_batch(
            make_decision_batch(cat, n=10, resolve_p=0.80, error_p=0.06, escalate_p=0.10,
                                base_time=recent, agent_version="v1.1")
        )

    return tc, store, config


# ── HTML report ────────────────────────────────────────────────────────────────

class TestHtmlReport:
    def test_returns_200(self, client):
        tc, *_ = client
        resp = tc.get("/governance/report/html")
        assert resp.status_code == 200

    def test_content_type_is_html(self, client):
        tc, *_ = client
        resp = tc.get("/governance/report/html")
        assert "text/html" in resp.headers["content-type"]

    def test_contains_doctype(self, client):
        tc, *_ = client
        resp = tc.get("/governance/report/html")
        assert "<!DOCTYPE html>" in resp.text

    def test_contains_governance_title(self, client):
        tc, *_ = client
        resp = tc.get("/governance/report/html")
        assert "Governance" in resp.text

    def test_contains_status_section(self, client):
        tc, *_ = client
        resp = tc.get("/governance/report/html")
        body = resp.text
        assert "Normal Metrics" in body
        assert "Governance Signals" in body

    def test_reflects_decision_data(self, populated_client):
        tc, store, _ = populated_client
        resp = tc.get("/governance/report/html")
        assert resp.status_code == 200
        assert "billing_dispute" in resp.text

    def test_no_external_resources(self, client):
        tc, *_ = client
        resp = tc.get("/governance/report/html")
        # Must not reference any external CDN or resource
        assert "cdn." not in resp.text
        assert 'src="http' not in resp.text
        assert 'href="http' not in resp.text


# ── Prometheus metrics ─────────────────────────────────────────────────────────

class TestPrometheusMetrics:
    def test_returns_200(self, client):
        tc, *_ = client
        resp = tc.get("/prometheus/metrics")
        assert resp.status_code == 200

    def test_content_type_is_plain_text(self, client):
        tc, *_ = client
        resp = tc.get("/prometheus/metrics")
        assert "text/plain" in resp.headers["content-type"]

    def test_contains_help_lines(self, client):
        tc, *_ = client
        resp = tc.get("/prometheus/metrics")
        assert "# HELP" in resp.text
        assert "# TYPE" in resp.text

    def test_contains_required_metrics(self, client):
        tc, *_ = client
        resp = tc.get("/prometheus/metrics")
        body = resp.text
        assert "governance_alerts_active" in body
        assert "governance_rollback_active" in body

    def test_drift_score_metric_present_with_data(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/prometheus/metrics")
        assert "governance_drift_score" in resp.text

    def test_decisions_total_metric_present_with_data(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/prometheus/metrics")
        assert "governance_decisions_total" in resp.text


# ── Preflight endpoint ─────────────────────────────────────────────────────────

_GOOD_DECISION = {
    "case_category": "routine",
    "risk_level": "low",
    "decision": "Resolved the issue.",
    "confidence": 0.90,
    "flags": [],
}

_HIGH_RISK_DECISION = {
    "case_category": "billing_dispute",
    "risk_level": "high",
    "decision": "Escalate billing dispute.",
    "confidence": 0.85,
    "flags": ["high_value"],
}


class TestPreflightEndpoint:
    def test_returns_200(self, client):
        tc, *_ = client
        resp = tc.post("/governance/preflight", json={
            "decisions": [_GOOD_DECISION],
            "agent_version": "v1.0",
        })
        assert resp.status_code == 200

    def test_response_has_recommendation(self, client):
        tc, *_ = client
        resp = tc.post("/governance/preflight", json={
            "decisions": [_GOOD_DECISION],
            "agent_version": "v1.0",
        })
        body = resp.json()
        assert "recommendation" in body
        assert body["recommendation"] in ("SAFE_TO_DEPLOY", "WARNING", "BLOCKED")

    def test_response_fields_present(self, client):
        tc, *_ = client
        resp = tc.post("/governance/preflight", json={
            "decisions": [_GOOD_DECISION],
            "agent_version": "v1.0",
        })
        body = resp.json()
        required = {"passed", "agent_version", "total_submitted", "valid_decisions",
                    "schema_error_count", "recommendation", "summary",
                    "threshold_violations", "high_risk_failures", "category_results"}
        assert required.issubset(body.keys())

    def test_agent_version_echoed(self, client):
        tc, *_ = client
        resp = tc.post("/governance/preflight", json={
            "decisions": [_GOOD_DECISION],
            "agent_version": "test-v9.9",
        })
        assert resp.json()["agent_version"] == "test-v9.9"

    def test_total_submitted_matches_input(self, client):
        tc, *_ = client
        decisions = [_GOOD_DECISION] * 5
        resp = tc.post("/governance/preflight", json={
            "decisions": decisions,
            "agent_version": "v1.0",
        })
        assert resp.json()["total_submitted"] == 5

    def test_invalid_schema_increases_error_count(self, client):
        tc, *_ = client
        bad_decision = {"garbage": "data", "risk_level": "invalid"}
        resp = tc.post("/governance/preflight", json={
            "decisions": [bad_decision],
            "agent_version": "v1.0",
        })
        assert resp.status_code == 200
        assert resp.json()["schema_error_count"] >= 1

    def test_empty_decisions_returns_422(self, client):
        tc, *_ = client
        resp = tc.post("/governance/preflight", json={
            "decisions": [],
            "agent_version": "v1.0",
        })
        assert resp.status_code == 422

    def test_high_risk_decisions_pass_when_correct(self, client):
        tc, *_ = client
        decisions = [_HIGH_RISK_DECISION] * 10
        resp = tc.post("/governance/preflight", json={
            "decisions": decisions,
            "agent_version": "v2.0",
        })
        body = resp.json()
        assert body["recommendation"] in ("SAFE_TO_DEPLOY", "WARNING")


# ── Agent version endpoints ────────────────────────────────────────────────────

class TestAgentVersions:
    def test_versions_empty_returns_empty_list(self, client):
        tc, *_ = client
        resp = tc.get("/governance/versions")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_versions_returns_list_with_data(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/versions")
        assert resp.status_code == 200
        versions = resp.json()
        assert len(versions) >= 2
        version_strs = [v["agent_version"] for v in versions]
        assert "v1.0" in version_strs
        assert "v1.1" in version_strs

    def test_version_summary_fields(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/versions")
        v = resp.json()[0]
        required = {"agent_version", "total", "resolution_rate", "error_rate",
                    "escalation_rate", "mean_confidence", "first_seen", "last_seen"}
        assert required.issubset(v.keys())

    def test_version_decisions_returns_404_for_unknown(self, client):
        tc, *_ = client
        resp = tc.get("/governance/versions/nonexistent-version/decisions")
        assert resp.status_code == 404

    def test_version_decisions_returns_data(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/versions/v1.0/decisions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] > 0
        assert "decisions" in body

    def test_version_decisions_filtered_by_category(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/versions/v1.0/decisions?category=billing_dispute")
        assert resp.status_code == 200
        body = resp.json()
        for d in body["decisions"]:
            assert d["category"] == "billing_dispute"

    def test_version_decisions_invalid_category_returns_404(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/versions/v1.0/decisions?category=made_up_category")
        assert resp.status_code == 404


# ── Version comparison ─────────────────────────────────────────────────────────

class TestVersionComparison:
    def test_compare_returns_200(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/versions/v1.0/compare/v1.1")
        assert resp.status_code == 200

    def test_compare_has_verdict(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/versions/v1.0/compare/v1.1")
        body = resp.json()
        assert "verdict" in body
        assert body["verdict"] in ("IMPROVED", "DEGRADED", "STABLE", "INSUFFICIENT_DATA")

    def test_compare_response_fields(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/versions/v1.0/compare/v1.1")
        body = resp.json()
        required = {"version_a", "version_b", "total_a", "total_b",
                    "resolution_rate_delta", "error_rate_delta", "verdict", "notes"}
        assert required.issubset(body.keys())

    def test_compare_unknown_version_a_returns_404(self, client):
        tc, *_ = client
        resp = tc.get("/governance/versions/ghost-v1/compare/ghost-v2")
        assert resp.status_code == 404

    def test_compare_versions_echoed(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/versions/v1.0/compare/v1.1")
        body = resp.json()
        assert body["version_a"] == "v1.0"
        assert body["version_b"] == "v1.1"

    def test_insufficient_data_when_too_few_decisions(self, client):
        tc, store, _ = client
        now = datetime.utcnow()
        # Only 2 decisions each — below min_sample=5
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, n=2, resolve_p=0.8,
                                error_p=0.1, escalate_p=0.1,
                                base_time=now - timedelta(hours=1),
                                agent_version="va")
        )
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.ROUTINE, n=2, resolve_p=0.8,
                                error_p=0.1, escalate_p=0.1,
                                base_time=now - timedelta(hours=1),
                                agent_version="vb")
        )
        resp = tc.get("/governance/versions/va/compare/vb")
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "INSUFFICIENT_DATA"


# ── Event broker status ────────────────────────────────────────────────────────

class TestEventBrokerStatus:
    def test_returns_200(self, client):
        tc, *_ = client
        resp = tc.get("/governance/events/status")
        assert resp.status_code == 200

    def test_has_required_fields(self, client):
        tc, *_ = client
        resp = tc.get("/governance/events/status")
        body = resp.json()
        assert "subscriber_count" in body
        assert "published_total" in body

    def test_subscriber_count_is_zero_initially(self, client):
        tc, *_ = client
        resp = tc.get("/governance/events/status")
        assert resp.json()["subscriber_count"] == 0


# ── Category decisions drill-down ──────────────────────────────────────────────

class TestCategoryDecisions:
    def test_returns_200_for_valid_category(self, client):
        tc, *_ = client
        resp = tc.get("/governance/categories/billing_dispute/decisions")
        assert resp.status_code == 200

    def test_returns_404_for_unknown_category(self, client):
        tc, *_ = client
        resp = tc.get("/governance/categories/made_up_category/decisions")
        assert resp.status_code == 404

    def test_returns_422_for_invalid_outcome_filter(self, client):
        tc, *_ = client
        resp = tc.get("/governance/categories/billing_dispute/decisions?outcome=invalid_outcome")
        assert resp.status_code == 422

    def test_returns_empty_when_no_data(self, client):
        tc, *_ = client
        resp = tc.get("/governance/categories/billing_dispute/decisions")
        body = resp.json()
        assert body["total"] == 0
        assert body["decisions"] == []

    def test_returns_decisions_with_data(self, populated_client):
        tc, *_ = populated_client
        resp = tc.get("/governance/categories/billing_dispute/decisions?hours=24")
        assert resp.status_code == 200
        body = resp.json()
        assert "total" in body
        assert "decisions" in body
        assert "resolution_rate" in body

    def test_outcome_filter_applied(self, populated_client):
        tc, store, _ = populated_client
        resp = tc.get("/governance/categories/billing_dispute/decisions?outcome=resolved&hours=720")
        assert resp.status_code == 200
        body = resp.json()
        for d in body["decisions"]:
            assert d["outcome"] == "resolved"


# ── Category drift history ─────────────────────────────────────────────────────

class TestCategoryHistory:
    def test_returns_200(self, client):
        tc, *_ = client
        resp = tc.get("/governance/categories/billing_dispute/history")
        assert resp.status_code == 200

    def test_returns_404_for_unknown_category(self, client):
        tc, *_ = client
        resp = tc.get("/governance/categories/made_up/history")
        assert resp.status_code == 404

    def test_empty_when_no_history(self, client):
        tc, *_ = client
        resp = tc.get("/governance/categories/billing_dispute/history")
        body = resp.json()
        assert body["points"] == []
        assert body["current_drift_score"] == 0.0

    def test_has_trend_field(self, client):
        tc, *_ = client
        resp = tc.get("/governance/categories/billing_dispute/history")
        body = resp.json()
        assert "trend" in body
        assert body["trend"] in ("improving", "stable", "degrading", "unknown")


# ── Scheduler status ───────────────────────────────────────────────────────────

class TestSchedulerStatus:
    def test_returns_200(self, client):
        tc, *_ = client
        resp = tc.get("/scheduler/status")
        assert resp.status_code == 200

    def test_has_running_field(self, client):
        tc, *_ = client
        resp = tc.get("/scheduler/status")
        assert "running" in resp.json()

    def test_scheduler_not_running_when_unconfigured(self, client):
        tc, *_ = client
        resp = tc.get("/scheduler/status")
        assert resp.json()["running"] is False

    def test_run_now_when_no_scheduler(self, client):
        tc, *_ = client
        resp = tc.post("/scheduler/run-now")
        assert resp.status_code in (200, 503)


# ── Alert acknowledgement ──────────────────────────────────────────────────────

class TestAlertAcknowledgement:
    def test_acknowledge_nonexistent_returns_404(self, client):
        tc, *_ = client
        resp = tc.post("/governance/alerts/does-not-exist/acknowledge")
        assert resp.status_code == 404


# ── Rollback resolution ────────────────────────────────────────────────────────

class TestRollbackResolution:
    def test_resolve_with_note(self, client):
        tc, *_ = client
        resp = tc.post("/governance/rollback/resolve", json={"note": "Manual review passed"})
        assert resp.status_code == 200
        body = resp.json()
        assert "resolved" in body

    def test_resolve_without_note_returns_422(self, client):
        tc, *_ = client
        resp = tc.post("/governance/rollback/resolve", json={})
        assert resp.status_code == 422


# ── build_html_report() unit-level smoke test ──────────────────────────────────

class TestBuildHtmlReport:
    def test_returns_string(self):
        from src.api.html_report import build_html_report
        from src.governance.config import GovernanceConfig
        from src.ingestion.store import DecisionStore

        store = DecisionStore()
        config = GovernanceConfig.default()
        html = build_html_report(store, config)
        assert isinstance(html, str)
        assert len(html) > 1000

    def test_custom_title_in_output(self):
        from src.api.html_report import build_html_report
        from src.governance.config import GovernanceConfig
        from src.ingestion.store import DecisionStore

        store = DecisionStore()
        config = GovernanceConfig.default()
        html = build_html_report(store, config, title="My Custom Title")
        assert "My Custom Title" in html

    def test_title_is_html_escaped(self):
        from src.api.html_report import build_html_report
        from src.governance.config import GovernanceConfig
        from src.ingestion.store import DecisionStore

        store = DecisionStore()
        config = GovernanceConfig.default()
        html = build_html_report(store, config, title='<script>alert("xss")</script>')
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_rollback_banner_present_when_active(self):
        from src.api.html_report import build_html_report
        from src.governance.config import GovernanceConfig
        from src.governance.schema import RollbackEvent
        from src.ingestion.store import DecisionStore

        store = DecisionStore()
        config = GovernanceConfig.default()
        event = RollbackEvent(
            reason="Critical drift detected",
            triggered_by="test",
            drift_score=1.0,
        )
        store.store_rollback_event(event)
        html = build_html_report(store, config)
        assert "rollback-banner" in html
        assert "Critical drift detected" in html

    def test_no_data_placeholder_shown(self):
        from src.api.html_report import build_html_report
        from src.governance.config import GovernanceConfig
        from src.ingestion.store import DecisionStore

        store = DecisionStore()
        config = GovernanceConfig.default()
        html = build_html_report(store, config)
        assert "no-data" in html or "No decisions" in html or "No drift data" in html
