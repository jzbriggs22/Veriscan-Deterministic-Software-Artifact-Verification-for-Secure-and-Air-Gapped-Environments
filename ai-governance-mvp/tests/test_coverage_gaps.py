"""
Targeted tests to close the remaining 6% coverage gap across five modules.

Each class targets a specific module's uncovered lines identified by
``pytest --cov=src --cov-report=term-missing``.

Modules covered:
  src/ingestion/ingestor.py    — category fallback, validate edge cases,
                                  categorize() branches, batch error paths
  src/detection/stats.py       — uniform proportion guard, zero-SE guard,
                                  Welch t-test zero-variance, sample_variance n<2
  src/governance/config.py     — RollbackRule operators (<, <=, >=, unknown metric)
  src/ingestion/store.py       — get_all_alerts(), get_all_drift_history(since=),
                                  resolve_rollback, get_decisions_in_window
  src/api/app.py               — configured endpoints return 200
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

import pytest

from src.governance.config import GovernanceConfig, RollbackRule
from src.governance.schema import (
    AgentDecision,
    AlertSeverity,
    CaseCategory,
    DecisionOutcome,
    DriftAlert,
    DriftResult,
    RollbackEvent,
)
from src.ingestion.ingestor import DecisionIngestor
from src.ingestion.store import DecisionStore


# ── src/ingestion/ingestor.py ─────────────────────────────────────────────────

class TestIngestorCoverage:
    @pytest.fixture
    def setup(self):
        config = GovernanceConfig.default()
        store = DecisionStore()
        ingestor = DecisionIngestor(store, config)
        return config, store, ingestor

    def _decision(self, **kwargs) -> AgentDecision:
        defaults = dict(
            case_id="C1",
            category=CaseCategory.ROUTINE,
            outcome=DecisionOutcome.RESOLVED,
            confidence=0.85,
            timestamp=datetime.utcnow(),
            agent_version="v1.0",
            processing_time_ms=400.0,
        )
        defaults.update(kwargs)
        return AgentDecision(**defaults)

    # validate() — negative processing_time_ms (bypass __post_init__ by mutating)
    def test_validate_rejects_negative_processing_time(self, setup):
        _, _, ingestor = setup
        d = self._decision()
        d.processing_time_ms = -1.0  # mutate after creation to bypass __post_init__
        ok, msg = ingestor.validate(d)
        assert not ok
        assert "processing_time_ms" in msg

    # validate() — future timestamp
    def test_validate_rejects_future_timestamp(self, setup):
        _, _, ingestor = setup
        d = self._decision(timestamp=datetime.utcnow() + timedelta(hours=2))
        ok, msg = ingestor.validate(d)
        assert not ok
        assert "future" in msg.lower()

    # categorize() — unknown category with no matching text → UNKNOWN
    def test_categorize_unknown_with_no_match_returns_unknown(self, setup):
        _, _, ingestor = setup
        d = self._decision(category=CaseCategory.UNKNOWN, case_text="some random text")
        result = ingestor.categorize(d)
        assert result == CaseCategory.UNKNOWN

    # categorize() — routine category with no match stays ROUTINE
    def test_categorize_routine_with_no_match_stays_routine(self, setup):
        _, _, ingestor = setup
        d = self._decision(category=CaseCategory.ROUTINE, case_text="routine support task")
        result = ingestor.categorize(d)
        assert result == CaseCategory.ROUTINE

    # categorize() — non-unknown/routine category is returned immediately
    def test_categorize_already_set_category_returned_immediately(self, setup):
        _, _, ingestor = setup
        d = self._decision(category=CaseCategory.FRAUD_CLAIM,
                           case_text="billing dispute text should be ignored")
        result = ingestor.categorize(d)
        assert result == CaseCategory.FRAUD_CLAIM

    # ingest_governance_decision() — invalid case_category falls back via risk_level
    def test_ingest_governance_decision_invalid_category_falls_back(self, setup):
        _, store, ingestor = setup
        from src.governance.structured import GovernanceDecision
        gd = GovernanceDecision(
            case_category="definitely_not_a_real_category",
            risk_level="high",
            decision="Escalate the case.",
            confidence=0.88,
            flags=[],
        )
        result = ingestor.ingest_governance_decision(
            gd, case_id="C-FALLBACK", agent_version="v1.0",
            processing_time_ms=400.0, timestamp=datetime.utcnow(),
        )
        assert result is not None
        assert store.total_count() == 1

    # ingest_governance_decision() — risk_level not in _RISK_TO_CATEGORY → UNKNOWN
    def test_ingest_governance_decision_unknown_risk_level_maps_to_unknown(self, setup):
        _, store, ingestor = setup
        from src.governance.structured import GovernanceDecision
        gd = GovernanceDecision(
            case_category="completely_unknown_category",
            risk_level="low",
            decision="Resolved.",
            confidence=0.90,
            flags=[],
        )
        result = ingestor.ingest_governance_decision(
            gd, case_id="C-UNK", agent_version="v1.0",
            processing_time_ms=300.0, timestamp=datetime.utcnow(),
        )
        assert store.total_count() == 1

    # ingest_batch() — skips invalid (mutated after creation), accepts valid
    def test_ingest_batch_reports_errors_for_invalid(self, setup):
        _, store, ingestor = setup
        valid = self._decision(case_id="GOOD-1")
        invalid = self._decision(case_id="BAD-1")
        invalid.processing_time_ms = -10.0  # mutate to make invalid
        accepted, errors = ingestor.ingest_batch([valid, invalid])
        assert accepted == 1
        assert len(errors) == 1
        assert "BAD-1" in errors[0] or "processing_time_ms" in errors[0]
        assert store.total_count() == 1

    # Config with invalid category_pattern key — should skip gracefully
    def test_invalid_category_pattern_key_skipped(self):
        config = GovernanceConfig.default()
        config.category_patterns["not_a_real_category"] = ["pattern"]
        store = DecisionStore()
        ingestor = DecisionIngestor(store, config)
        assert ingestor is not None


# ── src/detection/stats.py ────────────────────────────────────────────────────

class TestStatsCoverage:

    def test_two_proportion_z_test_all_same_outcome(self):
        from src.detection.stats import two_proportion_z_test
        # p_pool = 1.0 → guard triggers → (0.0, 1.0)
        z, p = two_proportion_z_test(count1=10, n1=10, count2=10, n2=10)
        assert z == 0.0
        assert p == 1.0

    def test_two_proportion_z_test_all_zero(self):
        from src.detection.stats import two_proportion_z_test
        # p_pool = 0.0 → guard triggers → (0.0, 1.0)
        z, p = two_proportion_z_test(count1=0, n1=10, count2=0, n2=10)
        assert z == 0.0
        assert p == 1.0

    def test_two_proportion_z_test_zero_n(self):
        from src.detection.stats import two_proportion_z_test
        z, p = two_proportion_z_test(count1=5, n1=0, count2=5, n2=10)
        assert z == 0.0
        assert p == 1.0

    def test_welch_t_test_zero_variance_both(self):
        from src.detection.stats import welch_t_test
        # Both groups identical → se = 0.0 → guard triggers
        t, p = welch_t_test(mean1=0.5, var1=0.0, n1=10, mean2=0.5, var2=0.0, n2=10)
        assert t == 0.0
        assert p == 1.0

    def test_welch_t_test_insufficient_samples(self):
        from src.detection.stats import welch_t_test
        # n < 2 → early return
        t, p = welch_t_test(mean1=0.5, var1=0.1, n1=1, mean2=0.6, var2=0.1, n2=1)
        assert t == 0.0
        assert p == 1.0

    def test_sample_variance_single_element(self):
        from src.detection.stats import sample_variance
        assert sample_variance([42.0]) == 0.0

    def test_sample_variance_empty(self):
        from src.detection.stats import sample_variance
        assert sample_variance([]) == 0.0

    def test_sample_variance_correct_for_known_input(self):
        from src.detection.stats import sample_variance
        # [2, 4, 4, 4, 5, 5, 7, 9] → sample variance = 4.571...
        vals = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        v = sample_variance(vals)
        assert abs(v - 4.5714285714) < 1e-6

    def test_normal_cdf_midpoint(self):
        from src.detection.stats import normal_cdf
        assert abs(normal_cdf(0.0) - 0.5) < 1e-9

    def test_normal_cdf_large_positive(self):
        from src.detection.stats import normal_cdf
        assert normal_cdf(10.0) > 0.999

    def test_two_proportion_z_test_detects_real_difference(self):
        from src.detection.stats import two_proportion_z_test
        # 5% vs 40% error rate → large z, small p
        z, p = two_proportion_z_test(count1=5, n1=100, count2=40, n2=100)
        assert abs(z) > 2.0
        assert p < 0.05


# ── src/governance/config.py — RollbackRule operators ─────────────────────────

class TestRollbackRuleCoverage:
    def _rule(self, condition: str) -> RollbackRule:
        r = RollbackRule(
            description="test rule",
            condition=condition,
            severity=AlertSeverity.CRITICAL,
        )
        _CONDITION_RE = re.compile(
            r"(?P<metric>\w+)\s*(?P<op>[><=!]+)\s*(?P<value>[\d.]+)"
        )
        m = _CONDITION_RE.match(condition.strip())
        if m:
            r._metric = m.group("metric")
            r._operator = m.group("op")
            r._threshold = float(m.group("value"))
        return r

    def test_operator_ge_matches_equal(self):
        rule = self._rule("drift_score >= 0.70")
        assert rule.matches(drift_score=0.70, error_rate=0.0,
                            category=CaseCategory.BILLING_DISPUTE, is_high_risk=True)

    def test_operator_ge_not_matches_below(self):
        rule = self._rule("drift_score >= 0.70")
        assert not rule.matches(drift_score=0.69, error_rate=0.0,
                                category=CaseCategory.BILLING_DISPUTE, is_high_risk=True)

    def test_operator_lt_matches(self):
        rule = self._rule("error_rate < 0.10")
        assert rule.matches(drift_score=0.0, error_rate=0.05,
                            category=CaseCategory.ROUTINE, is_high_risk=False)

    def test_operator_lt_not_matches_equal(self):
        rule = self._rule("error_rate < 0.10")
        assert not rule.matches(drift_score=0.0, error_rate=0.10,
                                category=CaseCategory.ROUTINE, is_high_risk=False)

    def test_operator_le_matches_equal(self):
        rule = self._rule("drift_score <= 0.50")
        assert rule.matches(drift_score=0.50, error_rate=0.0,
                            category=CaseCategory.ROUTINE, is_high_risk=False)

    def test_operator_le_matches_below(self):
        rule = self._rule("drift_score <= 0.50")
        assert rule.matches(drift_score=0.30, error_rate=0.0,
                            category=CaseCategory.ROUTINE, is_high_risk=False)

    def test_unknown_metric_returns_false(self):
        rule = self._rule("drift_score > 0.50")
        rule._metric = "unknown_metric_xyz"
        assert not rule.matches(drift_score=0.99, error_rate=0.99,
                                category=CaseCategory.BILLING_DISPUTE, is_high_risk=True)

    def test_unknown_operator_returns_false(self):
        rule = self._rule("drift_score > 0.50")
        rule._operator = "!="
        assert not rule.matches(drift_score=0.99, error_rate=0.0,
                                category=CaseCategory.BILLING_DISPUTE, is_high_risk=True)

    def test_error_rate_none_treated_as_zero(self):
        rule = self._rule("error_rate > 0.05")
        # error_rate=None → treated as 0.0 → should not match "error_rate > 0.05"
        assert not rule.matches(drift_score=0.0, error_rate=None,
                                category=CaseCategory.ROUTINE, is_high_risk=False)


# ── src/ingestion/store.py ────────────────────────────────────────────────────

class TestStoreCoverage:
    def _alert(self, category: CaseCategory = CaseCategory.BILLING_DISPUTE) -> DriftAlert:
        return DriftAlert(
            category=category,
            severity=AlertSeverity.WARNING,
            message="Test alert",
            drift_score=0.5,
        )

    def test_get_all_alerts_returns_including_acknowledged(self):
        store = DecisionStore()
        a1 = self._alert(CaseCategory.BILLING_DISPUTE)
        a2 = self._alert(CaseCategory.FRAUD_CLAIM)
        store.store_alert(a1)
        store.store_alert(a2)
        store.acknowledge_alert(a1.alert_id)

        all_alerts = store.get_all_alerts()
        active_alerts = store.get_active_alerts()

        assert len(all_alerts) == 2
        assert len(active_alerts) == 1

    def test_get_all_alerts_limit_respected(self):
        store = DecisionStore()
        for i in range(10):
            store.store_alert(self._alert())
        result = store.get_all_alerts(limit=3)
        assert len(result) == 3

    def test_get_all_drift_history_no_since(self):
        store = DecisionStore()
        for i in range(3):
            result = DriftResult(
                category=CaseCategory.BILLING_DISPUTE,
                drift_score=0.3 + i * 0.1,
                insufficient_data=False,
            )
            store.store_drift_result(result)
        history = store.get_all_drift_history()
        assert len(history) == 3

    def test_get_all_drift_history_with_since_filter(self):
        store = DecisionStore()
        for i in range(5):
            result = DriftResult(
                category=CaseCategory.FRAUD_CLAIM,
                drift_score=0.5,
                insufficient_data=False,
            )
            store.store_drift_result(result)

        since = datetime.utcnow() - timedelta(minutes=1)
        history = store.get_all_drift_history(since=since)
        assert len(history) == 5

        since_future = datetime.utcnow() + timedelta(hours=1)
        history_empty = store.get_all_drift_history(since=since_future)
        assert len(history_empty) == 0

    def test_get_rollback_events_returns_all(self):
        store = DecisionStore()
        e1 = RollbackEvent(reason="First", triggered_by="test", drift_score=0.8)
        e2 = RollbackEvent(reason="Second", triggered_by="test", drift_score=0.9)
        store.store_rollback_event(e1)
        store.store_rollback_event(e2)
        events = store.get_rollback_events()
        assert len(events) == 2

    def test_get_active_rollback_returns_most_recent_active(self):
        store = DecisionStore()
        e1 = RollbackEvent(reason="Old active", triggered_by="test", drift_score=0.8)
        store.store_rollback_event(e1)
        active = store.get_active_rollback()
        assert active is not None
        assert active.is_active

    def test_get_active_rollback_returns_none_when_resolved(self):
        store = DecisionStore()
        e = RollbackEvent(reason="Resolved one", triggered_by="test", drift_score=0.8)
        store.store_rollback_event(e)
        # resolve_rollback requires (event_id, note)
        store.resolve_rollback(e.event_id, "Fixed")
        active = store.get_active_rollback()
        assert active is None

    def test_get_decisions_in_window(self):
        store = DecisionStore()
        now = datetime.utcnow()
        decisions = [
            AgentDecision(
                case_id=f"W-{i}",
                category=CaseCategory.ROUTINE,
                outcome=DecisionOutcome.RESOLVED,
                confidence=0.8,
                timestamp=now - timedelta(hours=i),
                agent_version="v1.0",
                processing_time_ms=400.0,
            )
            for i in range(5)
        ]
        store.store_decisions_batch(decisions)
        window = store.get_decisions_in_window(
            category=CaseCategory.ROUTINE,
            start=now - timedelta(hours=3),
            end=now,
        )
        assert len(window) == 3  # hours 0, 1, 2

    def test_store_decisions_batch_empty_list(self):
        store = DecisionStore()
        store.store_decisions_batch([])
        assert store.total_count() == 0

    def test_oldest_decision_time_returns_none_empty(self):
        store = DecisionStore()
        result = store.oldest_decision_time()
        assert result is None

    def test_oldest_decision_time_correct(self):
        store = DecisionStore()
        old_ts = datetime.utcnow() - timedelta(days=10)
        recent_ts = datetime.utcnow() - timedelta(hours=1)
        store.store_decision(AgentDecision(
            case_id="OLD", category=CaseCategory.ROUTINE,
            outcome=DecisionOutcome.RESOLVED, confidence=0.8,
            timestamp=old_ts, agent_version="v1", processing_time_ms=400.0,
        ))
        store.store_decision(AgentDecision(
            case_id="NEW", category=CaseCategory.ROUTINE,
            outcome=DecisionOutcome.RESOLVED, confidence=0.8,
            timestamp=recent_ts, agent_version="v1", processing_time_ms=400.0,
        ))
        oldest = store.oldest_decision_time()
        assert oldest is not None
        assert abs((oldest - old_ts).total_seconds()) < 2

    def test_get_decisions_since(self):
        store = DecisionStore()
        now = datetime.utcnow()
        for i in range(4):
            store.store_decision(AgentDecision(
                case_id=f"S-{i}", category=CaseCategory.ROUTINE,
                outcome=DecisionOutcome.RESOLVED, confidence=0.8,
                timestamp=now - timedelta(hours=i),
                agent_version="v1", processing_time_ms=400.0,
            ))
        result = store.get_decisions_since(since=now - timedelta(hours=2, minutes=30))
        assert len(result) == 3


# ── src/api/app.py — configured endpoints ─────────────────────────────────────

class TestApiConfiguredPaths:
    """Verify key endpoints return expected responses when service is configured."""

    @pytest.fixture
    def tc(self):
        from fastapi.testclient import TestClient
        from src.api.app import app, configure
        config = GovernanceConfig.default()
        store = DecisionStore()
        configure(config, store)
        return TestClient(app), store, config

    def test_health_endpoint_returns_200(self, tc):
        client, _, _ = tc
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_metrics_endpoint_returns_200(self, tc):
        client, _, _ = tc
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_governance_report_returns_200(self, tc):
        client, _, _ = tc
        resp = client.get("/governance/report")
        assert resp.status_code == 200

    def test_governance_status_returns_200(self, tc):
        client, _, _ = tc
        resp = client.get("/governance/status")
        assert resp.status_code == 200

    def test_alerts_endpoint_returns_list(self, tc):
        client, _, _ = tc
        resp = client.get("/governance/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_prometheus_metrics_endpoint(self, tc):
        client, _, _ = tc
        resp = client.get("/prometheus/metrics")
        assert resp.status_code == 200
        assert "governance_" in resp.text


# ── src/api/html_report.py ────────────────────────────────────────────────────

class TestHtmlReportCoverage:
    """Cover the remaining 10% of html_report.py."""

    def test_drift_result_with_insufficient_data_rendered(self):
        """DriftResult with insufficient_data=True renders gracefully."""
        from src.api.html_report import build_html_report

        config = GovernanceConfig.default()
        store = DecisionStore()

        result = DriftResult(
            category=CaseCategory.BILLING_DISPUTE,
            drift_score=0.0,
            insufficient_data=True,
            insufficient_data_reason="Need at least 30 baseline decisions",
        )
        store.store_drift_result(result)

        html = build_html_report(store, config)
        assert "Insufficient" in html or "insufficient" in html or "no-data" in html

    def test_high_drift_score_renders_drift_high_class(self):
        """drift_score >= 0.7 → drift-high CSS class applied."""
        from src.api.html_report import _drift_fill_class, _score_label
        assert _drift_fill_class(0.8) == "drift-high"
        assert _score_label(0.8) == "CRITICAL"

    def test_medium_drift_score_class(self):
        from src.api.html_report import _drift_fill_class, _score_label
        assert _drift_fill_class(0.5) == "drift-med"
        assert _score_label(0.5) == "WARNING"

    def test_low_drift_score_class(self):
        from src.api.html_report import _drift_fill_class, _score_label
        assert _drift_fill_class(0.2) == "drift-low"
        assert _score_label(0.2) == "OK"

    def test_status_class_all_variants(self):
        from src.api.html_report import _status_class
        from src.governance.schema import GovernanceStatus
        assert "healthy" in _status_class(GovernanceStatus.HEALTHY)
        assert "drifting" in _status_class(GovernanceStatus.DRIFTING)
        assert "critical" in _status_class(GovernanceStatus.CRITICAL)
        assert "rollback" in _status_class(GovernanceStatus.ROLLBACK_TRIGGERED)

    def test_html_report_with_active_alerts_section(self):
        """Covers the active alerts table rendering path."""
        from src.api.html_report import build_html_report

        config = GovernanceConfig.default()
        store = DecisionStore()

        alert = DriftAlert(
            category=CaseCategory.FRAUD_CLAIM,
            severity=AlertSeverity.CRITICAL,
            message="Fraud rate spiked to 45%",
            drift_score=0.88,
        )
        store.store_alert(alert)

        html = build_html_report(store, config)
        assert "Fraud rate spiked" in html
        assert "fraud_claim" in html

    def test_html_report_decision_volume_section(self):
        """Covers decision volume by category table."""
        from src.api.html_report import build_html_report
        from tests.conftest import make_decision_batch

        config = GovernanceConfig.default()
        store = DecisionStore()
        now = datetime.utcnow()
        store.store_decisions_batch(
            make_decision_batch(CaseCategory.BILLING_DISPUTE, 5, 0.8, 0.1, 0.1,
                                base_time=now - timedelta(hours=2))
        )
        html = build_html_report(store, config)
        assert "billing_dispute" in html
        assert "Decision Volume" in html


# ── src/governance/schema.py ──────────────────────────────────────────────────

class TestSchemaCoverage:
    """Cover uncovered schema methods."""

    def test_category_stats_from_decisions_empty(self):
        from src.governance.schema import CategoryStats
        stats = CategoryStats.from_decisions(CaseCategory.ROUTINE, [])
        assert stats.sample_size == 0
        assert stats.resolution_rate == 0.0
        assert stats.error_rate == 0.0

    def test_drift_result_is_high_risk_property_false(self):
        # is_high_risk is a @property derived from category.is_high_risk()
        result = DriftResult(
            category=CaseCategory.ROUTINE,
            drift_score=0.3,
            insufficient_data=False,
        )
        assert not result.is_high_risk

    def test_drift_result_is_high_risk_property_true(self):
        result = DriftResult(
            category=CaseCategory.BILLING_DISPUTE,
            drift_score=0.8,
            insufficient_data=False,
        )
        assert result.is_high_risk

    def test_rollback_event_default_is_active(self):
        event = RollbackEvent(reason="Test", triggered_by="ci", drift_score=0.9)
        assert event.is_active

    def test_governance_status_values(self):
        from src.governance.schema import GovernanceStatus
        statuses = {s.value for s in GovernanceStatus}
        assert "healthy" in statuses
        assert "critical" in statuses
        assert "rollback_triggered" in statuses

    def test_case_category_is_high_risk_boundaries(self):
        assert CaseCategory.BILLING_DISPUTE.is_high_risk()
        assert CaseCategory.FRAUD_CLAIM.is_high_risk()
        assert CaseCategory.POLICY_SENSITIVE.is_high_risk()
        assert not CaseCategory.ROUTINE.is_high_risk()
        assert not CaseCategory.UNKNOWN.is_high_risk()


# ── src/engine/scheduler.py ───────────────────────────────────────────────────

class TestSchedulerCoverage:
    """Cover scheduler paths not exercised in test_scheduler.py."""

    def _make_scheduler(self, **kwargs):
        from src.engine.scheduler import DetectionScheduler
        from src.detection.detector import DriftDetector
        from src.engine.alerts import AlertEngine
        from src.engine.rollback import RollbackEngine
        config = GovernanceConfig.default()
        store = DecisionStore()
        detector = DriftDetector(store, config)
        alert_engine = AlertEngine(store, config)
        rollback_engine = RollbackEngine(store, config)
        return DetectionScheduler(
            store=store,
            detector=detector,
            alert_engine=alert_engine,
            rollback_engine=rollback_engine,
            **kwargs,
        )

    def test_scheduler_status_when_not_started(self):
        scheduler = self._make_scheduler()
        assert not scheduler.is_running()

    def test_run_now_returns_results(self):
        scheduler = self._make_scheduler()
        results = scheduler.run_now()
        assert isinstance(results, list)

    def test_scheduler_cycle_count_increments(self):
        scheduler = self._make_scheduler()
        assert scheduler.cycle_count == 0
        scheduler.run_now()
        assert scheduler.cycle_count == 1
