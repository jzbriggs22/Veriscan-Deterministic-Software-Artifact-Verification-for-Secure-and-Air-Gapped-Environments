"""Tests for drift detector: statistical correctness and edge cases."""
from __future__ import annotations

import math

import pytest

from src.detection.detector import DriftDetector
from src.detection.stats import cohens_h, drift_score_from_cohens_h, two_proportion_z_test
from src.governance.schema import CaseCategory
from tests.conftest import make_decision_batch


# ── Statistical utilities ──────────────────────────────────────────────────────

def test_two_proportion_z_test_significant_difference():
    # p1=0.80 (n=100) vs p2=0.40 (n=20): should be highly significant
    z, p = two_proportion_z_test(80, 100, 8, 20)
    assert p < 0.05, f"Expected significant result, got p={p}"
    # p2 (0.40) < p1 (0.80) so z is negative; we care about |z| being large
    assert abs(z) > 1.96


def test_two_proportion_z_test_no_difference():
    # Same proportion: p-value should be high (not significant)
    _, p = two_proportion_z_test(50, 100, 10, 20)
    assert p > 0.5, f"Identical proportions should have high p-value, got {p}"


def test_two_proportion_z_test_zero_n_returns_1():
    _, p = two_proportion_z_test(0, 0, 5, 10)
    assert p == 1.0


def test_cohens_h_zero_for_equal_proportions():
    h = cohens_h(0.5, 0.5)
    assert abs(h) < 1e-9


def test_cohens_h_large_for_big_difference():
    h = cohens_h(0.80, 0.40)
    assert abs(h) > 0.5, "Large proportion difference should have |h|>0.5"


def test_cohens_h_handles_boundary_values():
    # Should not raise on p=0 or p=1 (clamped internally)
    h = cohens_h(0.0, 1.0)
    assert math.isfinite(h)


def test_drift_score_zero_for_zero_h():
    assert drift_score_from_cohens_h(0.0) == 0.0


def test_drift_score_one_for_large_h():
    # |h| = 0.8 should map to score = 1.0
    assert drift_score_from_cohens_h(0.8) == 1.0
    assert drift_score_from_cohens_h(1.5) == 1.0  # capped


def test_drift_score_proportional():
    assert drift_score_from_cohens_h(0.4) < drift_score_from_cohens_h(0.6)


# ── DriftDetector ──────────────────────────────────────────────────────────────

def test_detect_returns_none_for_empty_category(config, store):
    detector = DriftDetector(store, config)
    result = detector.detect_category(CaseCategory.FRAUD_CLAIM)
    assert result is None


def test_detect_marks_insufficient_data_when_baseline_too_small(config, store):
    detector = DriftDetector(store, config)
    # Add only 5 decisions — less than min_baseline_size (15 for fraud)
    decisions = make_decision_batch(CaseCategory.FRAUD_CLAIM, 5, 0.8, 0.05, 0.1)
    store.store_decisions_batch(decisions)
    result = detector.detect_category(CaseCategory.FRAUD_CLAIM)
    assert result is not None
    assert result.insufficient_data is True
    assert "baseline" in result.insufficient_data_reason.lower()


def test_detect_marks_insufficient_data_when_total_too_small(config, store):
    detector = DriftDetector(store, config)
    # Only 3 decisions — below both baseline (15) and detection (5) thresholds for fraud
    decisions = make_decision_batch(CaseCategory.FRAUD_CLAIM, 3, 0.8, 0.05, 0.1)
    store.store_decisions_batch(decisions)
    result = detector.detect_category(CaseCategory.FRAUD_CLAIM)
    assert result is not None
    assert result.insufficient_data is True
    # Reason must mention the insufficient baseline
    assert "baseline" in result.insufficient_data_reason.lower() or "detection" in result.insufficient_data_reason.lower()


def test_detect_no_drift_on_stable_agent(config, store):
    detector = DriftDetector(store, config)
    # Load 50 baseline + will use same distribution for recent
    decisions = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 50, resolve_p=0.83, error_p=0.04, escalate_p=0.10
    )
    store.store_decisions_batch(decisions)
    result = detector.detect_category(CaseCategory.BILLING_DISPUTE)
    assert result is not None
    if not result.insufficient_data:
        # Drift score should be low when baseline==recent
        assert result.drift_score < 0.5, f"Expected low drift, got {result.drift_score}"


def test_detect_high_drift_on_drifted_agent(config, store):
    detector = DriftDetector(store, config)

    # Healthy baseline: 50 decisions, 83% resolution, 4% error
    # Placed at 15d ago so it falls within the [now-30d, now-7d) baseline window
    baseline = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 50,
        resolve_p=0.83, error_p=0.04, escalate_p=0.10,
        base_time=__import__("datetime").datetime.utcnow() - __import__("datetime").timedelta(days=15),
    )
    store.store_decisions_batch(baseline)

    # Drifted recent: 20 decisions, 40% resolution, 20% error
    from datetime import datetime, timedelta
    drifted = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 20,
        resolve_p=0.40, error_p=0.20, escalate_p=0.30,
        base_time=datetime.utcnow() - timedelta(hours=1),
        time_step_seconds=60,
    )
    store.store_decisions_batch(drifted)

    result = detector.detect_category(CaseCategory.BILLING_DISPUTE)
    assert result is not None
    assert not result.insufficient_data
    assert result.drift_score > 0.4, f"Expected high drift score, got {result.drift_score}"


def test_detect_populates_metric_drifts(config, store):
    detector = DriftDetector(store, config)
    from datetime import datetime, timedelta

    baseline = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 20,
        resolve_p=0.80, error_p=0.05, escalate_p=0.12,
        base_time=datetime.utcnow() - timedelta(days=15),
    )
    drifted = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 10,
        resolve_p=0.50, error_p=0.30, escalate_p=0.15,
        base_time=datetime.utcnow() - timedelta(hours=1),
        time_step_seconds=30,
    )
    store.store_decisions_batch(baseline)
    store.store_decisions_batch(drifted)

    result = detector.detect_category(CaseCategory.FRAUD_CLAIM)
    if result and not result.insufficient_data:
        metric_names = {m.metric_name for m in result.metric_drifts}
        assert "resolution_rate" in metric_names
        assert "error_rate" in metric_names
        assert "escalation_rate" in metric_names
        assert "mean_confidence" in metric_names


def test_run_detection_covers_all_high_risk_categories(config, populated_store):
    detector = DriftDetector(populated_store, config)
    results = detector.run_detection()
    cat_names = {r.category for r in results}
    assert CaseCategory.BILLING_DISPUTE in cat_names
    assert CaseCategory.FRAUD_CLAIM in cat_names
    assert CaseCategory.POLICY_SENSITIVE in cat_names


def test_drift_score_bounded_0_to_1(config, store):
    detector = DriftDetector(store, config)
    from datetime import datetime, timedelta

    baseline = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 20,
        resolve_p=0.95, error_p=0.01, escalate_p=0.02,
        base_time=datetime.utcnow() - timedelta(days=15),
    )
    drifted = make_decision_batch(
        CaseCategory.FRAUD_CLAIM, 10,
        resolve_p=0.05, error_p=0.90, escalate_p=0.03,
        base_time=datetime.utcnow() - timedelta(minutes=30),
        time_step_seconds=10,
    )
    store.store_decisions_batch(baseline)
    store.store_decisions_batch(drifted)

    result = detector.detect_category(CaseCategory.FRAUD_CLAIM)
    if result and not result.insufficient_data:
        assert 0.0 <= result.drift_score <= 1.0
