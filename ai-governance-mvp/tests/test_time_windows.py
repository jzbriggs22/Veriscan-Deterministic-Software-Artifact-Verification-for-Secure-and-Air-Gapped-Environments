"""Tests for time-anchored baseline and detection windows."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from src.detection.detector import DriftDetector
from src.governance.config import GovernanceConfig, TimeWindowConfig
from src.governance.schema import CaseCategory
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch


# ── Store: time-window query methods ──────────────────────────────────────────

def test_get_decisions_in_window_returns_only_matching(store):
    now = datetime.utcnow()
    old = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 10,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(days=20),
        time_step_seconds=300,
    )
    recent = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 10,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(hours=12),
        time_step_seconds=60,
    )
    store.store_decisions_batch(old)
    store.store_decisions_batch(recent)

    # Window from 30d ago to 1d ago should capture old but not recent
    window = store.get_decisions_in_window(
        CaseCategory.BILLING_DISPUTE,
        start=now - timedelta(days=30),
        end=now - timedelta(days=1),
    )
    assert len(window) == 10
    for d in window:
        assert d.timestamp < now - timedelta(days=1)


def test_get_decisions_in_window_excludes_other_categories(store):
    now = datetime.utcnow()
    billing = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 5,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(days=10),
    )
    fraud = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 5,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(days=10),
    )
    store.store_decisions_batch(billing)
    store.store_decisions_batch(fraud)

    window = store.get_decisions_in_window(
        CaseCategory.BILLING_DISPUTE,
        start=now - timedelta(days=30),
        end=now,
    )
    assert len(window) == 5
    assert all(d.category == CaseCategory.BILLING_DISPUTE for d in window)


def test_get_baseline_window_excludes_recent(store):
    """Baseline window must not include data within the exclusion gap."""
    now = datetime.utcnow()
    # Data in the baseline band: [now-30d, now-7d)
    baseline_band = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 15,
        resolve_p=0.8, error_p=0.05, escalate_p=0.1,
        base_time=now - timedelta(days=25),
        time_step_seconds=3600,
    )
    # Data in the exclusion zone: [now-7d, now)
    recent_band = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 10,
        resolve_p=0.4, error_p=0.3, escalate_p=0.2,
        base_time=now - timedelta(days=5),
        time_step_seconds=3600,
    )
    store.store_decisions_batch(baseline_band)
    store.store_decisions_batch(recent_band)

    baseline = store.get_baseline_window(
        CaseCategory.FRAUD_CLAIM,
        baseline_lookback_days=30,
        baseline_exclusion_hours=168,  # 7 days
    )
    assert len(baseline) == 15
    cutoff = now - timedelta(hours=168)
    assert all(d.timestamp < cutoff for d in baseline)


def test_get_detection_window_returns_only_recent(store):
    now = datetime.utcnow()
    old = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 10,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(days=10),
        time_step_seconds=3600,
    )
    recent = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 5,
        resolve_p=0.4, error_p=0.2, escalate_p=0.3,
        base_time=now - timedelta(hours=20),
        time_step_seconds=900,
    )
    store.store_decisions_batch(old)
    store.store_decisions_batch(recent)

    detection = store.get_detection_window(CaseCategory.BILLING_DISPUTE, detection_hours=24)
    assert len(detection) == 5
    cutoff = now - timedelta(hours=24)
    assert all(d.timestamp >= cutoff for d in detection)


def test_get_decisions_since_returns_oldest_first(store):
    now = datetime.utcnow()
    decisions = make_decision_batch(
        CaseCategory.ROUTINE, 10,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(hours=5),
        time_step_seconds=600,
    )
    store.store_decisions_batch(decisions)

    since = now - timedelta(hours=3)
    result = store.get_decisions_since(since)
    assert all(d.timestamp >= since for d in result)
    for i in range(len(result) - 1):
        assert result[i].timestamp <= result[i + 1].timestamp


def test_oldest_decision_time_no_data(store):
    assert store.oldest_decision_time() is None


def test_oldest_decision_time_returns_minimum(store):
    now = datetime.utcnow()
    old = make_decision_batch(
        CaseCategory.ROUTINE, 5,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(days=10),
    )
    new = make_decision_batch(
        CaseCategory.ROUTINE, 5,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(days=1),
    )
    store.store_decisions_batch(old)
    store.store_decisions_batch(new)

    oldest = store.oldest_decision_time()
    assert oldest is not None
    assert oldest <= now - timedelta(days=9)


def test_oldest_decision_time_filtered_by_category(store):
    now = datetime.utcnow()
    billing = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 5,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(days=20),
    )
    fraud = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 5,
        resolve_p=0.8, error_p=0.1, escalate_p=0.1,
        base_time=now - timedelta(days=5),
    )
    store.store_decisions_batch(billing)
    store.store_decisions_batch(fraud)

    fraud_oldest = store.oldest_decision_time(CaseCategory.FRAUD_CLAIM)
    billing_oldest = store.oldest_decision_time(CaseCategory.BILLING_DISPUTE)
    assert fraud_oldest is not None and billing_oldest is not None
    assert billing_oldest < fraud_oldest


# ── DriftDetector: time-window mode ───────────────────────────────────────────

def _make_time_window_config(
    baseline_lookback_days: int = 30,
    baseline_exclusion_hours: int = 168,
    detection_hours: int = 24,
) -> GovernanceConfig:
    cfg = GovernanceConfig.default()
    cfg.time_window = TimeWindowConfig(
        baseline_lookback_days=baseline_lookback_days,
        baseline_exclusion_hours=baseline_exclusion_hours,
        detection_hours=detection_hours,
        use_time_windows=True,
    )
    return cfg


def test_time_window_detector_stable_agent(store):
    cfg = _make_time_window_config()
    now = datetime.utcnow()

    # Use large samples so sampling noise doesn't push a "stable" agent above
    # the threshold.  100-vs-50 gives Cohen's h near 0 when distributions match.
    baseline = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 100,
        resolve_p=0.83, error_p=0.04, escalate_p=0.10,
        base_time=now - timedelta(days=20),
        time_step_seconds=600,
    )
    recent = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 50,
        resolve_p=0.83, error_p=0.04, escalate_p=0.10,
        base_time=now - timedelta(hours=20),
        time_step_seconds=120,
    )
    store.store_decisions_batch(baseline)
    store.store_decisions_batch(recent)

    detector = DriftDetector(store, cfg)
    result = detector.detect_category(CaseCategory.BILLING_DISPUTE)
    assert result is not None
    if not result.insufficient_data:
        assert result.drift_score < 0.6, (
            f"Stable agent should show low drift, got {result.drift_score:.3f}"
        )


def test_time_window_detector_drifted_agent(store):
    cfg = _make_time_window_config()
    now = datetime.utcnow()

    # Large samples + extreme drift → Cohen's h well above threshold regardless of RNG state
    baseline = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 80,
        resolve_p=0.83, error_p=0.04, escalate_p=0.10,
        base_time=now - timedelta(days=20),
        time_step_seconds=600,
    )
    drifted = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 40,
        resolve_p=0.20, error_p=0.50, escalate_p=0.25,
        base_time=now - timedelta(hours=20),
        time_step_seconds=300,
    )
    store.store_decisions_batch(baseline)
    store.store_decisions_batch(drifted)

    detector = DriftDetector(store, cfg)
    result = detector.detect_category(CaseCategory.BILLING_DISPUTE)
    assert result is not None
    assert not result.insufficient_data
    assert result.drift_score > 0.4, f"Expected high drift, got {result.drift_score:.3f}"


def test_time_window_detector_insufficient_baseline(store):
    """When baseline band is empty, detector should report insufficient_data."""
    cfg = _make_time_window_config(
        baseline_lookback_days=30,
        baseline_exclusion_hours=168,
        detection_hours=24,
    )
    now = datetime.utcnow()
    # Data is in the detection window but there is nothing in the baseline band
    # [now-30d, now-7d). The detector should find data but flag insufficient baseline.
    recent = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 10,
        resolve_p=0.8, error_p=0.05, escalate_p=0.1,
        base_time=now - timedelta(hours=20),
        time_step_seconds=600,
    )
    store.store_decisions_batch(recent)

    detector = DriftDetector(store, cfg)
    result = detector.detect_category(CaseCategory.FRAUD_CLAIM)
    assert result is not None
    assert result.insufficient_data
    assert "baseline" in result.insufficient_data_reason.lower()


def test_time_window_detector_no_recent_data(store):
    """When detection window is empty (only old data), report insufficient_data."""
    cfg = _make_time_window_config(
        baseline_lookback_days=30,
        baseline_exclusion_hours=168,
        detection_hours=24,
    )
    now = datetime.utcnow()
    # Data is 10 days old — in baseline window but not detection window
    old = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 20,
        resolve_p=0.8, error_p=0.05, escalate_p=0.1,
        base_time=now - timedelta(days=10),
        time_step_seconds=1800,
    )
    store.store_decisions_batch(old)

    detector = DriftDetector(store, cfg)
    result = detector.detect_category(CaseCategory.FRAUD_CLAIM)
    assert result is not None
    assert result.insufficient_data
    assert "detection" in result.insufficient_data_reason.lower()


def test_count_based_fallback_still_works(store):
    """When use_time_windows=False, the count-based path is used."""
    cfg = GovernanceConfig.default()
    cfg.time_window = TimeWindowConfig(use_time_windows=False)
    now = datetime.utcnow()

    decisions = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 50,
        resolve_p=0.83, error_p=0.04, escalate_p=0.10,
        base_time=now - timedelta(days=7),
        time_step_seconds=300,
    )
    store.store_decisions_batch(decisions)

    detector = DriftDetector(store, cfg)
    result = detector.detect_category(CaseCategory.BILLING_DISPUTE)
    assert result is not None
    if not result.insufficient_data:
        assert 0.0 <= result.drift_score <= 1.0


def test_time_window_config_defaults():
    tw = TimeWindowConfig()
    assert tw.baseline_lookback_days == 30
    assert tw.baseline_exclusion_hours == 168
    assert tw.detection_hours == 24
    assert tw.use_time_windows is True


def test_governance_config_default_has_time_window():
    cfg = GovernanceConfig.default()
    assert isinstance(cfg.time_window, TimeWindowConfig)
    assert cfg.time_window.use_time_windows is True
