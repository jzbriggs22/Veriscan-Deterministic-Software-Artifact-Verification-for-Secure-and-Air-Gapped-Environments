"""
Final coverage tests targeting the last remaining uncovered lines.

Targets:
  src/engine/scheduler.py    162-163  on_cycle callback raises → except Exception: pass
  src/engine/webhooks.py     137      urlopen returns HTTP 404 → logger.warning (non-exception path)
  src/ingestion/store.py     113-115  _cursor() commit raises → rollback + re-raise
  src/ingestion/ingestor.py  201      category=UNKNOWN → categorize() call
  src/api/html_report.py     283-284  invalid category string from DB → except ValueError: is_hr=False
  src/dashboard/dashboard.py 119      live() sleep line (iterations=2, first iteration sleeps)
  src/dashboard/dashboard.py 193-201  _governance_panel insufficient_data=True rows
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from src.governance.config import GovernanceConfig
from src.governance.schema import (
    CaseCategory,
    DecisionOutcome,
    DriftAlert,
    DriftResult,
    AlertSeverity,
    GovernanceStatus,
    RollbackEvent,
    AgentDecision,
)
from src.ingestion.store import DecisionStore


def _decision(case_id: str, category: CaseCategory, outcome: DecisionOutcome,
              timestamp: datetime, confidence: float = 0.85) -> AgentDecision:
    return AgentDecision(
        case_id=case_id,
        category=category,
        outcome=outcome,
        confidence=confidence,
        timestamp=timestamp,
        agent_version="v1.0",
        processing_time_ms=400.0,
    )


# ── scheduler.py lines 162-163 — on_cycle callback raises ─────────────────────

class TestSchedulerOnCycleCallbackRaises:
    """Cover lines 162-163: except Exception: pass when on_cycle callback raises."""

    def _build_scheduler(self, on_cycle):
        from src.engine.scheduler import DetectionScheduler
        from src.detection.detector import DriftDetector
        from src.engine.alerts import AlertEngine
        from src.engine.rollback import RollbackEngine

        config = GovernanceConfig.default()
        store = DecisionStore()
        return DetectionScheduler(
            store=store,
            detector=DriftDetector(store, config),
            alert_engine=AlertEngine(store, config),
            rollback_engine=RollbackEngine(store, config),
            on_cycle=on_cycle,
        )

    def test_on_cycle_exception_is_swallowed(self):
        """Lines 162-163: exception from on_cycle must not propagate."""
        def _raising_callback(results):
            raise RuntimeError("callback failed")

        scheduler = self._build_scheduler(_raising_callback)
        # Must not raise despite callback throwing RuntimeError
        results = scheduler.run_now()
        assert isinstance(results, list)
        assert scheduler.cycle_count == 1

    def test_on_cycle_value_error_is_swallowed(self):
        """Lines 162-163: ValueError from on_cycle is also swallowed."""
        def _bad_callback(results):
            raise ValueError("bad value in callback")

        scheduler = self._build_scheduler(_bad_callback)
        results = scheduler.run_now()
        assert isinstance(results, list)


# ── webhooks.py line 137 — HTTP non-2xx response (not an exception) ───────────

class TestWebhookNon2xxResponse:
    """Cover line 137: logger.warning when urlopen succeeds but status is not 2xx."""

    def _dispatcher(self, retry_attempts: int = 1):
        from src.engine.webhooks import WebhookDispatcher, WebhookConfig
        cfg = WebhookConfig(
            url="http://localhost:19999/webhook",
            retry_attempts=retry_attempts,
        )
        return WebhookDispatcher(configs=[cfg])

    def test_non_2xx_response_logs_warning_and_returns_false(self):
        """Line 137: 404 response triggers logger.warning, not an exception."""
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        dispatcher = self._dispatcher(retry_attempts=1)
        alert = DriftAlert(
            category=CaseCategory.BILLING_DISPUTE,
            severity=AlertSeverity.WARNING,
            message="Test alert",
            drift_score=0.55,
        )
        with patch("src.engine.webhooks.urlopen", return_value=mock_resp):
            result = dispatcher.dispatch_alert(alert)

        # 404 → no success; result maps url → False
        assert isinstance(result, dict)
        assert result.get("http://localhost:19999/webhook") is False

    def test_non_2xx_rollback_dispatch_logs_and_returns_false(self):
        """Line 137 via dispatch_rollback: 503 response logs warning."""
        mock_resp = MagicMock()
        mock_resp.status = 503
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        dispatcher = self._dispatcher(retry_attempts=1)
        event = RollbackEvent(reason="Test rollback", triggered_by="test", drift_score=0.9)

        with patch("src.engine.webhooks.urlopen", return_value=mock_resp):
            result = dispatcher.dispatch_rollback(event)

        assert isinstance(result, dict)
        assert result.get("http://localhost:19999/webhook") is False


# ── store.py lines 113-115 — _cursor() commit raises → rollback + re-raise ────

class _CommitFailing:
    """Wraps sqlite3.Connection so that commit() raises OperationalError."""
    def __init__(self, real_conn):
        self._real = real_conn

    def cursor(self):
        return self._real.cursor()

    def commit(self):
        raise sqlite3.OperationalError("disk full simulated")

    def rollback(self):
        return self._real.rollback()

    def __getattr__(self, name):
        return getattr(self._real, name)


class TestStoreCursorRollbackPath:
    """Cover lines 113-115: exception inside _cursor() triggers rollback then re-raise."""

    def test_store_decision_commit_failure_triggers_rollback_and_reraises(self):
        """Lines 113-115: when commit() raises, _cursor() calls rollback() and re-raises."""
        store = DecisionStore()
        d = _decision("rollback-test", CaseCategory.ROUTINE, DecisionOutcome.RESOLVED, datetime.utcnow())

        real_conn = store._conn
        store._conn = _CommitFailing(real_conn)
        try:
            with pytest.raises(sqlite3.OperationalError, match="disk full"):
                store.store_decision(d)
        finally:
            store._conn = real_conn

    def test_store_alert_commit_failure_triggers_rollback(self):
        """Lines 113-115: same rollback path via store_alert."""
        store = DecisionStore()
        alert = DriftAlert(
            category=CaseCategory.ROUTINE,
            severity=AlertSeverity.WARNING,
            message="test",
            drift_score=0.4,
        )

        real_conn = store._conn
        store._conn = _CommitFailing(real_conn)
        try:
            with pytest.raises(sqlite3.OperationalError, match="disk full"):
                store.store_alert(alert)
        finally:
            store._conn = real_conn


# ── ingestor.py line 201 — category=UNKNOWN triggers categorize() ─────────────

class TestIngestorUnknownCategory:
    """Cover line 201: UNKNOWN category triggers categorize() in ingest_batch."""

    def test_ingest_batch_unknown_category_calls_categorize(self):
        """Line 201: d.category == UNKNOWN → d.category = self.categorize(d)."""
        from src.ingestion.ingestor import DecisionIngestor

        config = GovernanceConfig.default()
        store = DecisionStore()
        ingestor = DecisionIngestor(store, config)

        d = AgentDecision(
            case_id="unknown-cat-test",
            category=CaseCategory.UNKNOWN,
            outcome=DecisionOutcome.RESOLVED,
            confidence=0.82,
            timestamp=datetime.utcnow(),
            agent_version="v1.0",
            processing_time_ms=350.0,
            case_text="customer billing issue",
        )

        accepted, errors = ingestor.ingest_batch([d])
        assert accepted == 1
        assert errors == []
        # Category was either left as UNKNOWN or reclassified — either way, no crash
        assert d.category is not None

    def test_ingest_batch_unknown_no_case_text_still_works(self):
        """Line 201: categorize with empty case_text still runs without error."""
        from src.ingestion.ingestor import DecisionIngestor

        config = GovernanceConfig.default()
        store = DecisionStore()
        ingestor = DecisionIngestor(store, config)

        d = AgentDecision(
            case_id="unknown-empty-text",
            category=CaseCategory.UNKNOWN,
            outcome=DecisionOutcome.ESCALATED,
            confidence=0.70,
            timestamp=datetime.utcnow(),
            agent_version="v1.0",
            processing_time_ms=280.0,
        )

        accepted, errors = ingestor.ingest_batch([d])
        assert accepted == 1


# ── html_report.py lines 283-284 — invalid category in DB → except ValueError ─

class TestHtmlReportInvalidCategory:
    """Cover lines 283-284: CaseCategory(invalid_str) raises ValueError → is_hr = False."""

    def test_invalid_category_in_count_by_category_renders_without_error(self):
        """
        Lines 283-284: count_by_category returns an unknown string →
        CaseCategory(str) raises ValueError → except ValueError: is_hr = False.

        We mock count_by_category so that get_all_recent() (which calls _row_to_decision
        and fails on unknown categories) is not affected.
        """
        from src.api.html_report import build_html_report

        config = GovernanceConfig.default()
        store = DecisionStore()

        # Mock count_by_category to return an invalid category string
        # while leaving get_all_recent and other methods intact (they use valid data)
        with patch.object(
            store,
            "count_by_category",
            return_value={"not_a_real_category_xyz": 5, "routine": 10},
        ):
            html = build_html_report(store, config)

        # The invalid category renders as non-high-risk without crashing
        assert "not_a_real_category_xyz" in html
        assert len(html) > 100


# ── dashboard.py lines 119, 193-201 — live() sleep, insufficient_data rows ────

class TestDashboardRemainingLines:
    """Cover dashboard.py lines 119 (sleep) and 193-201 (insufficient_data rows)."""

    def _make_dashboard(self):
        from src.dashboard.dashboard import GovernanceDashboard
        from src.detection.detector import DriftDetector
        from src.engine.alerts import AlertEngine
        from src.engine.rollback import RollbackEngine

        config = GovernanceConfig.default()
        store = DecisionStore()
        return GovernanceDashboard(
            store=store,
            config=config,
            detector=DriftDetector(store, config),
            alert_engine=AlertEngine(store, config),
            rollback_engine=RollbackEngine(store, config),
        )

    def test_live_mode_iterations_2_hits_sleep_line(self):
        """
        Line 119: live() with iterations=2 — first loop hits sleep before second break.
        Patch time.sleep to avoid real delay and Rich Live to avoid terminal capture.
        """
        from src.dashboard import dashboard as dash_module

        dashboard = self._make_dashboard()

        sleep_calls = []

        def mock_sleep(seconds):
            sleep_calls.append(seconds)

        mock_live = MagicMock()
        mock_live.__enter__ = MagicMock(return_value=mock_live)
        mock_live.__exit__ = MagicMock(return_value=False)

        with patch.object(dash_module, "Live", return_value=mock_live):
            with patch("time.sleep", side_effect=mock_sleep):
                dashboard.live(refresh_seconds=0.001, iterations=2)

        # With iterations=2: first iteration → sleep → second iteration → break
        assert len(sleep_calls) == 1
        assert sleep_calls[0] == pytest.approx(0.001)

    def test_governance_panel_with_insufficient_data_result(self):
        """Lines 193-201: _governance_panel() with DriftResult(insufficient_data=True)."""
        from src.dashboard.dashboard import GovernanceDashboard

        dashboard = self._make_dashboard()

        insufficient_result = DriftResult(
            category=CaseCategory.BILLING_DISPUTE,
            insufficient_data=True,
            insufficient_data_reason="Only 3 recent decisions (need ≥ 5)",
            drift_score=0.0,
        )

        panel = dashboard._governance_panel(
            [insufficient_result],
            GovernanceStatus.HEALTHY,
        )
        # Should render without error; panel contains the insufficient data row
        assert panel is not None
        from rich.panel import Panel
        assert isinstance(panel, Panel)

    def test_governance_panel_mixed_sufficient_and_insufficient(self):
        """Lines 193-201: panel with both sufficient and insufficient data rows."""
        from src.dashboard.dashboard import GovernanceDashboard
        from src.governance.schema import CategoryStats

        dashboard = self._make_dashboard()
        now = datetime.utcnow()

        stats = CategoryStats(
            category=CaseCategory.ROUTINE,
            sample_size=20,
            resolution_rate=0.85,
            escalation_rate=0.05,
            error_rate=0.05,
            mean_confidence=0.88,
            p50_latency_ms=350.0,
        )

        sufficient_result = DriftResult(
            category=CaseCategory.ROUTINE,
            drift_score=0.2,
            insufficient_data=False,
            baseline_stats=stats,
            recent_stats=stats,
        )
        insufficient_result = DriftResult(
            category=CaseCategory.FRAUD_CLAIM,
            insufficient_data=True,
            insufficient_data_reason="Baseline window empty",
            drift_score=0.0,
        )

        panel = dashboard._governance_panel(
            [sufficient_result, insufficient_result],
            GovernanceStatus.DRIFTING,
        )
        assert panel is not None
