"""
Regression tests for the consistency fixes:

  1. Timezone-aware ISO-8601 timestamps are normalized to naive UTC at the
     schema boundary instead of blowing up on naive-vs-aware comparisons.
  2. All governance surfaces derive overall status through the shared
     compute_status(), which honors per-category config thresholds and
     promotes an active rollback to the top-level status.
  3. The status endpoint speaks the GovernanceStatus enum vocabulary
     ("rollback_triggered", not the former "rollback_active").
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from src.governance.config import GovernanceConfig
from src.governance.schema import (
    AgentDecision,
    CaseCategory,
    DecisionOutcome,
    DriftResult,
    GovernanceStatus,
    RollbackEvent,
)
from src.governance.status import compute_status
from src.ingestion.store import DecisionStore


def _configured_client():
    from src.api.app import app, configure
    config = GovernanceConfig.default()
    store = DecisionStore()
    configure(config, store)
    return TestClient(app), store, config


def _decision_payload(case_id: str, timestamp: str) -> dict:
    return {
        "case_id": case_id,
        "category": "routine",
        "outcome": "resolved",
        "confidence": 0.9,
        "agent_version": "v1.0",
        "processing_time_ms": 100.0,
        "timestamp": timestamp,
    }


# ── Timestamp normalization ───────────────────────────────────────────────────

class TestTimestampNormalization:
    def test_aware_timestamp_normalized_to_naive_utc_in_schema(self):
        aware = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone(timedelta(hours=2)))
        d = AgentDecision(
            case_id="tz-schema",
            category=CaseCategory.ROUTINE,
            outcome=DecisionOutcome.RESOLVED,
            confidence=0.9,
            timestamp=aware,
            agent_version="v1.0",
            processing_time_ms=100.0,
        )
        assert d.timestamp.tzinfo is None
        assert d.timestamp == datetime(2026, 7, 18, 10, 0, 0)

    def test_naive_timestamp_left_untouched(self):
        naive = datetime(2026, 7, 18, 10, 0, 0)
        d = AgentDecision(
            case_id="tz-naive",
            category=CaseCategory.ROUTINE,
            outcome=DecisionOutcome.RESOLVED,
            confidence=0.9,
            timestamp=naive,
            agent_version="v1.0",
            processing_time_ms=100.0,
        )
        assert d.timestamp is naive

    def test_api_accepts_zulu_and_offset_timestamps(self):
        tc, store, _ = _configured_client()
        for i, ts in enumerate(
            ["2026-07-18T10:00:00Z", "2026-07-18T12:00:00+02:00", "2026-07-18T10:00:00"]
        ):
            resp = tc.post("/decisions", json=_decision_payload(f"TZ-{i}", ts))
            assert resp.status_code == 201
            assert resp.json() == {"accepted": 1, "rejected": 0, "errors": []}

        # All three represent the same UTC instant and round-trip identically.
        stored = store.get_all_recent(limit=10)
        assert len(stored) == 3
        assert {d.timestamp for d in stored} == {datetime(2026, 7, 18, 10, 0, 0)}

    def test_future_aware_timestamp_rejected_with_clean_message(self):
        tc, _, _ = _configured_client()
        future = (datetime.utcnow() + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = tc.post("/decisions", json=_decision_payload("TZ-future", future))
        assert resp.status_code == 201
        body = resp.json()
        assert body["rejected"] == 1
        assert "future" in body["errors"][0]


# ── Shared status derivation ──────────────────────────────────────────────────

def _result(category: CaseCategory, score: float, insufficient: bool = False) -> DriftResult:
    return DriftResult(
        category=category,
        drift_score=score,
        insufficient_data=insufficient,
        insufficient_data_reason="not enough data" if insufficient else "",
    )


class TestComputeStatus:
    def setup_method(self):
        self.config = GovernanceConfig.default()

    def test_rollback_wins_over_everything(self):
        results = [_result(CaseCategory.BILLING_DISPUTE, 1.0)]
        assert (
            compute_status(results, self.config, rollback_active=True)
            is GovernanceStatus.ROLLBACK_TRIGGERED
        )

    def test_critical_when_category_exceeds_its_critical_threshold(self):
        thr = self.config.thresholds_for(CaseCategory.BILLING_DISPUTE)
        results = [_result(CaseCategory.BILLING_DISPUTE, thr.critical_score)]
        assert (
            compute_status(results, self.config, rollback_active=False)
            is GovernanceStatus.CRITICAL
        )

    def test_drifting_when_between_warning_and_critical(self):
        thr = self.config.thresholds_for(CaseCategory.ROUTINE)
        score = (thr.warning_score + thr.critical_score) / 2
        results = [_result(CaseCategory.ROUTINE, score)]
        assert (
            compute_status(results, self.config, rollback_active=False)
            is GovernanceStatus.DRIFTING
        )

    def test_healthy_below_all_thresholds(self):
        results = [
            _result(CaseCategory.ROUTINE, 0.0),
            _result(CaseCategory.FRAUD_CLAIM, 0.05),
        ]
        assert (
            compute_status(results, self.config, rollback_active=False)
            is GovernanceStatus.HEALTHY
        )

    def test_insufficient_data_results_are_ignored(self):
        results = [_result(CaseCategory.BILLING_DISPUTE, 1.0, insufficient=True)]
        assert (
            compute_status(results, self.config, rollback_active=False)
            is GovernanceStatus.HEALTHY
        )

    def test_custom_config_thresholds_are_honored(self):
        # Tighten the routine critical threshold below the score: a score that
        # is healthy under defaults must become critical under custom config.
        config = GovernanceConfig.default()
        default_thr = config.thresholds_for(CaseCategory.ROUTINE)
        score = default_thr.warning_score / 2  # healthy under defaults
        results = [_result(CaseCategory.ROUTINE, score)]
        assert (
            compute_status(results, config, rollback_active=False)
            is GovernanceStatus.HEALTHY
        )

        config.default_thresholds.warning_score = score / 4
        config.default_thresholds.critical_score = score / 2
        assert (
            compute_status(results, config, rollback_active=False)
            is GovernanceStatus.CRITICAL
        )


# ── Surfaces agree on rollback ────────────────────────────────────────────────

class TestSurfacesReflectRollback:
    def test_report_endpoint_status_is_rollback_triggered_when_active(self):
        tc, store, _ = _configured_client()
        store.store_rollback_event(
            RollbackEvent(reason="drift gate tripped", triggered_by="test", drift_score=0.9)
        )
        resp = tc.get("/governance/report")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == GovernanceStatus.ROLLBACK_TRIGGERED.value
        assert body["active_rollback"] is not None

    def test_status_endpoint_uses_enum_vocabulary(self):
        tc, store, _ = _configured_client()
        store.store_rollback_event(
            RollbackEvent(reason="drift gate tripped", triggered_by="test", drift_score=0.9)
        )
        resp = tc.get("/governance/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "rollback_triggered"
        assert body["rollback_active"] is True

    def test_html_report_shows_rollback_status(self):
        from src.api.html_report import build_html_report

        config = GovernanceConfig.default()
        store = DecisionStore()
        store.store_rollback_event(
            RollbackEvent(reason="drift gate tripped", triggered_by="test", drift_score=0.9)
        )
        html = build_html_report(store, config)
        assert "ROLLBACK_TRIGGERED" in html

    def test_report_and_status_agree_when_healthy(self):
        tc, _, _ = _configured_client()
        report = tc.get("/governance/report").json()
        status = tc.get("/governance/status").json()
        assert report["status"] == "healthy"
        assert status["status"] == "healthy"
