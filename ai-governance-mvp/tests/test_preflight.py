"""
Tests for pre-flight validation, agent version tracking/comparison,
and the behavioral conftest rollback hook.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from src.governance.config import GovernanceConfig
from src.governance.preflight import PreflightValidator
from src.governance.schema import CaseCategory
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch
from tests.fixtures.decisions import (
    BILLING_FIXTURES,
    FRAUD_FIXTURES,
    POLICY_FIXTURES,
    ROUTINE_FIXTURES,
    SCHEMA_DICTS,
    FIXTURE_DECISIONS,
)


def _schema_only(d: dict) -> dict:
    return {k: v for k, v in d.items() if not k.startswith("_")}


# ── PreflightValidator ─────────────────────────────────────────────────────────

class TestPreflightValidator:

    @pytest.fixture
    def validator(self):
        return PreflightValidator(GovernanceConfig.default())

    def test_all_50_fixtures_pass_preflight(self, validator):
        report = validator.validate_batch(FIXTURE_DECISIONS, agent_version="behavioral-v1")
        # All 50 parse as valid GovernanceDecision — schema errors = 0
        assert report.schema_error_count == 0
        assert report.valid_decisions == 50

    def test_healthy_billing_batch_passes(self, validator):
        report = validator.validate_batch(BILLING_FIXTURES, agent_version="v1.0")
        assert report.schema_error_count == 0
        assert report.valid_decisions == len(BILLING_FIXTURES)

    def test_recommendation_safe_to_deploy_on_healthy_fixtures(self, validator):
        # Use only routine fixtures — low risk, high resolution rate
        report = validator.validate_batch(ROUTINE_FIXTURES, agent_version="v1.0")
        assert report.recommendation in ("SAFE_TO_DEPLOY", "WARNING")

    def test_schema_error_counted_correctly(self, validator):
        bad_decisions = [
            {"case_category": "billing_dispute", "risk_level": "INVALID_LEVEL",
             "decision": "ok", "confidence": 0.9},
            _schema_only(BILLING_FIXTURES[0]),
        ]
        report = validator.validate_batch(bad_decisions, agent_version="v1.0")
        assert report.schema_error_count == 1
        assert report.valid_decisions == 1

    def test_blocked_when_error_rate_too_high(self, validator):
        # Build a batch where all decisions have error-triggering text
        drifted = [
            {"case_category": "billing_dispute", "risk_level": "high",
             "decision": f"Error: cannot process case {i}.", "confidence": 0.3, "flags": []}
            for i in range(20)
        ]
        report = validator.validate_batch(drifted, agent_version="v-bad")
        # billing_dispute threshold max_error_rate=0.12; 100% error rate → BLOCKED
        assert report.recommendation == "BLOCKED"
        assert not report.passed
        assert len(report.threshold_violations) > 0

    def test_high_risk_failure_detected(self, validator):
        # fraud_claim with risk_level=low should be flagged
        bad_risk = [
            {"case_category": "fraud_claim", "risk_level": "low",
             "decision": "Resolved: no fraud detected.", "confidence": 0.9, "flags": []}
        ] * 10
        report = validator.validate_batch(bad_risk, agent_version="v-lowrisk")
        assert len(report.high_risk_failures) > 0
        assert not report.passed

    def test_expected_category_mismatch_flagged(self, validator):
        # Add _expected_category annotation that doesn't match case_category
        mismatched = [
            {"case_category": "routine", "risk_level": "low",
             "decision": "Resolved.", "confidence": 0.9, "flags": [],
             "_expected_category": "billing_dispute"}  # mismatch
        ]
        report = validator.validate_batch(mismatched, agent_version="v1.0")
        assert len(report.high_risk_failures) > 0

    def test_report_has_category_results(self, validator):
        report = validator.validate_batch(BILLING_FIXTURES + ROUTINE_FIXTURES, agent_version="v1.0")
        categories = {r.category for r in report.category_results}
        assert "billing_dispute" in categories
        assert "routine" in categories

    def test_validate_governance_decisions_convenience(self, validator):
        from src.governance.structured import GovernanceDecision
        decisions = [GovernanceDecision.model_validate(_schema_only(d)) for d in ROUTINE_FIXTURES]
        report = validator.validate_governance_decisions(decisions, agent_version="v1.0")
        assert report.schema_error_count == 0

    def test_empty_batch_produces_report(self, validator):
        report = validator.validate_batch([], agent_version="v1.0")
        assert report.total_submitted == 0
        assert report.valid_decisions == 0

    def test_agent_version_preserved_in_report(self, validator):
        report = validator.validate_batch(SCHEMA_DICTS, agent_version="v3.14.1")
        assert report.agent_version == "v3.14.1"

    def test_generated_at_is_recent(self, validator):
        before = datetime.utcnow()
        report = validator.validate_batch(SCHEMA_DICTS, agent_version="v1.0")
        after = datetime.utcnow()
        assert before <= report.generated_at <= after

    def test_to_dict_serializable(self, validator):
        report = validator.validate_batch(SCHEMA_DICTS, agent_version="v1.0")
        d = report.to_dict()
        assert isinstance(d, dict)
        assert "passed" in d
        assert "recommendation" in d
        assert "category_results" in d

    def test_all_50_fixtures_pass_schema_validation(self, validator):
        """The 50-fixture behavioral dataset must have zero schema errors."""
        report = validator.validate_batch(FIXTURE_DECISIONS, agent_version="behavioral-v1")
        assert report.schema_error_count == 0, (
            f"Schema errors in fixture dataset: {report.threshold_violations}"
        )

    def test_below_min_detection_size_is_violation(self, validator):
        # Only 1 decision; min_detection_size for billing_dispute=5
        tiny = [_schema_only(BILLING_FIXTURES[0])]
        report = validator.validate_batch(tiny, agent_version="v1.0")
        # Should have a threshold violation about min sample size
        assert any("minimum" in v.lower() for v in report.threshold_violations)


# ── API: preflight endpoint ────────────────────────────────────────────────────

class TestPreflightAPI:

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from src.api.app import app, configure
        config = GovernanceConfig.default()
        store = DecisionStore()
        configure(config, store)
        return TestClient(app)

    def test_preflight_returns_200(self, client):
        resp = client.post("/governance/preflight", json={
            "agent_version": "v1.0",
            "decisions": [_schema_only(d) for d in ROUTINE_FIXTURES],
        })
        assert resp.status_code == 200

    def test_preflight_response_has_recommendation(self, client):
        resp = client.post("/governance/preflight", json={
            "agent_version": "v1.0",
            "decisions": SCHEMA_DICTS,
        })
        body = resp.json()
        assert "recommendation" in body
        assert body["recommendation"] in ("SAFE_TO_DEPLOY", "WARNING", "BLOCKED")

    def test_preflight_blocked_on_high_error_rate(self, client):
        drifted = [
            {"case_category": "billing_dispute", "risk_level": "high",
             "decision": f"Error: cannot process {i}.", "confidence": 0.3, "flags": []}
            for i in range(20)
        ]
        resp = client.post("/governance/preflight", json={
            "agent_version": "v-bad",
            "decisions": drifted,
        })
        body = resp.json()
        assert body["recommendation"] == "BLOCKED"
        assert not body["passed"]

    def test_preflight_safe_on_healthy_decisions(self, client):
        healthy = [_schema_only(d) for d in ROUTINE_FIXTURES]
        resp = client.post("/governance/preflight", json={
            "agent_version": "v-good",
            "decisions": healthy,
        })
        body = resp.json()
        assert body["recommendation"] in ("SAFE_TO_DEPLOY", "WARNING")

    def test_preflight_returns_category_breakdown(self, client):
        resp = client.post("/governance/preflight", json={
            "agent_version": "v1.0",
            "decisions": SCHEMA_DICTS,
        })
        body = resp.json()
        assert "category_results" in body
        assert len(body["category_results"]) > 0

    def test_preflight_counts_schema_errors(self, client):
        bad = [
            {"case_category": "billing_dispute", "risk_level": "NOPE",
             "decision": "ok", "confidence": 0.9},
        ] + [_schema_only(d) for d in ROUTINE_FIXTURES]
        resp = client.post("/governance/preflight", json={
            "agent_version": "v1.0",
            "decisions": bad,
        })
        body = resp.json()
        assert body["schema_error_count"] >= 1

    def test_preflight_empty_decisions_returns_400_or_422(self, client):
        resp = client.post("/governance/preflight", json={
            "agent_version": "v1.0",
            "decisions": [],
        })
        assert resp.status_code in (400, 422)


# ── Agent version store methods ────────────────────────────────────────────────

class TestVersionStore:

    @pytest.fixture
    def versioned_store(self):
        store = DecisionStore()
        now = datetime.utcnow()
        for version, resolve_p, error_p in [
            ("v1.0", 0.83, 0.04),
            ("v1.1", 0.78, 0.08),
            ("v2.0", 0.65, 0.20),
        ]:
            decisions = make_decision_batch(
                CaseCategory.BILLING_DISPUTE, 20,
                resolve_p=resolve_p, error_p=error_p, escalate_p=0.08,
                agent_version=version,
                base_time=now - timedelta(days=10),
            )
            store.store_decisions_batch(decisions)
        return store

    def test_get_agent_versions_returns_all(self, versioned_store):
        versions = versioned_store.get_agent_versions()
        assert set(versions) == {"v1.0", "v1.1", "v2.0"}

    def test_get_agent_versions_empty_store(self, store):
        assert store.get_agent_versions() == []

    def test_get_decisions_by_version(self, versioned_store):
        decisions = versioned_store.get_decisions_by_version("v1.0")
        assert all(d.agent_version == "v1.0" for d in decisions)

    def test_get_decisions_by_version_with_category(self, versioned_store):
        decisions = versioned_store.get_decisions_by_version(
            "v1.0", category=CaseCategory.BILLING_DISPUTE
        )
        assert all(d.category == CaseCategory.BILLING_DISPUTE for d in decisions)

    def test_get_decisions_by_unknown_version_returns_empty(self, versioned_store):
        decisions = versioned_store.get_decisions_by_version("v99.99")
        assert decisions == []

    def test_get_version_summary_keys(self, versioned_store):
        summary = versioned_store.get_version_summary("v1.0")
        assert summary["agent_version"] == "v1.0"
        assert summary["total"] == 20
        assert 0.0 <= summary["resolution_rate"] <= 1.0
        assert 0.0 <= summary["error_rate"] <= 1.0

    def test_get_version_summary_unknown_returns_empty(self, versioned_store):
        summary = versioned_store.get_version_summary("v99.99")
        assert summary == {}

    def test_get_version_summary_has_category_breakdown(self, versioned_store):
        summary = versioned_store.get_version_summary("v1.0")
        assert "decisions_by_category" in summary
        assert "billing_dispute" in summary["decisions_by_category"]


# ── API: version endpoints ─────────────────────────────────────────────────────

class TestVersionAPI:

    @pytest.fixture
    def client_versioned(self):
        from fastapi.testclient import TestClient
        from src.api.app import app, configure

        config = GovernanceConfig.default()
        store = DecisionStore()
        configure(config, store)
        now = datetime.utcnow()

        for version, resolve_p, error_p in [
            ("v1.0", 0.83, 0.04),
            ("v2.0", 0.65, 0.20),
        ]:
            decisions = make_decision_batch(
                CaseCategory.BILLING_DISPUTE, 20,
                resolve_p=resolve_p, error_p=error_p, escalate_p=0.08,
                agent_version=version,
                base_time=now - timedelta(days=10),
            )
            store.store_decisions_batch(decisions)

        return TestClient(app)

    def test_list_versions_returns_200(self, client_versioned):
        resp = client_versioned.get("/governance/versions")
        assert resp.status_code == 200

    def test_list_versions_contains_versions(self, client_versioned):
        resp = client_versioned.get("/governance/versions")
        body = resp.json()
        assert isinstance(body, list)
        versions = {v["agent_version"] for v in body}
        assert "v1.0" in versions
        assert "v2.0" in versions

    def test_version_summary_has_rates(self, client_versioned):
        resp = client_versioned.get("/governance/versions")
        body = resp.json()
        v1 = next(v for v in body if v["agent_version"] == "v1.0")
        assert 0.0 <= v1["resolution_rate"] <= 1.0
        assert 0.0 <= v1["error_rate"] <= 1.0
        assert v1["total"] == 20

    def test_version_decisions_returns_200(self, client_versioned):
        resp = client_versioned.get("/governance/versions/v1.0/decisions")
        assert resp.status_code == 200

    def test_version_decisions_filtered_by_version(self, client_versioned):
        resp = client_versioned.get("/governance/versions/v1.0/decisions")
        body = resp.json()
        for d in body["decisions"]:
            assert d["agent_version"] == "v1.0"

    def test_version_decisions_unknown_returns_404(self, client_versioned):
        resp = client_versioned.get("/governance/versions/v99.99/decisions")
        assert resp.status_code == 404

    def test_compare_versions_returns_200(self, client_versioned):
        resp = client_versioned.get("/governance/versions/v1.0/compare/v2.0")
        assert resp.status_code == 200

    def test_compare_versions_has_verdict(self, client_versioned):
        resp = client_versioned.get("/governance/versions/v1.0/compare/v2.0")
        body = resp.json()
        assert "verdict" in body
        assert body["verdict"] in ("IMPROVED", "DEGRADED", "STABLE", "INSUFFICIENT_DATA")

    def test_compare_versions_v2_degraded(self, client_versioned):
        # v2.0 has much higher error rate → should be DEGRADED
        resp = client_versioned.get("/governance/versions/v1.0/compare/v2.0")
        body = resp.json()
        assert body["verdict"] == "DEGRADED"
        assert body["error_rate_delta"] > 0  # b worse than a

    def test_compare_versions_delta_fields(self, client_versioned):
        resp = client_versioned.get("/governance/versions/v1.0/compare/v2.0")
        body = resp.json()
        assert "resolution_rate_delta" in body
        assert "error_rate_delta" in body
        assert "escalation_rate_delta" in body
        assert "confidence_delta" in body

    def test_compare_versions_unknown_a_returns_404(self, client_versioned):
        resp = client_versioned.get("/governance/versions/v99/compare/v2.0")
        assert resp.status_code == 404

    def test_compare_versions_unknown_b_returns_404(self, client_versioned):
        resp = client_versioned.get("/governance/versions/v1.0/compare/v99")
        assert resp.status_code == 404

    def test_compare_versions_notes_present(self, client_versioned):
        resp = client_versioned.get("/governance/versions/v1.0/compare/v2.0")
        body = resp.json()
        assert isinstance(body["notes"], list)
        assert len(body["notes"]) > 0

    def test_list_versions_empty_store(self):
        from fastapi.testclient import TestClient
        from src.api.app import app, configure
        config = GovernanceConfig.default()
        store = DecisionStore()
        configure(config, store)
        tc = TestClient(app)
        resp = tc.get("/governance/versions")
        assert resp.status_code == 200
        assert resp.json() == []


# ── Conftest behavioral hook ───────────────────────────────────────────────────

class TestConftestBehavioralHook:
    """Verify the pytest_runtest_logreport hook works correctly."""

    def test_behavioral_failures_list_is_accessible(self):
        from tests.conftest import _behavioral_failures, _behavioral_store
        # These exist at module level — confirms hook infrastructure is in place
        assert isinstance(_behavioral_failures, list)
        assert isinstance(_behavioral_store, DecisionStore)

    def test_behavioral_store_can_accept_rollback_event(self):
        from tests.conftest import _behavioral_store
        from src.governance.schema import RollbackEvent
        event = RollbackEvent(
            reason="Test verification — not a real failure",
            triggered_by="test_suite",
            drift_score=0.0,
        )
        _behavioral_store.store_rollback_event(event)
        # Just verifies no exception — the store is operational
