"""
Drift detector: compares recent agent behavior on high-risk cases against baseline.

The key insight: overall metrics (resolution rate, response time) often look
healthy while high-risk categories silently drift. This detector monitors
each category independently with per-category thresholds.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from ..governance.config import GovernanceConfig
from ..governance.schema import (
    CaseCategory,
    CategoryStats,
    DecisionOutcome,
    MetricDrift,
    DriftResult,
)
from ..ingestion.store import DecisionStore
from .stats import (
    cohens_h,
    drift_score_from_cohens_h,
    sample_variance,
    two_proportion_z_test,
    welch_t_test,
)


class DriftDetector:
    """
    Runs per-category drift detection on each call to run_detection().
    Compares the `detection_window` most-recent decisions against the
    `baseline_window` oldest decisions for each category.
    """

    def __init__(self, store: DecisionStore, config: GovernanceConfig) -> None:
        self._store = store
        self._config = config

    def run_detection(self) -> list[DriftResult]:
        """
        Run drift detection for all monitored categories.
        Returns a DriftResult per category (including ROUTINE as a control group).
        """
        categories = [hrc.category for hrc in self._config.high_risk_categories]
        # Also check ROUTINE as a sanity / control comparison
        categories.append(CaseCategory.ROUTINE)
        results = []
        for cat in categories:
            result = self.detect_category(cat)
            if result is not None:
                results.append(result)
        return results

    def detect_category(self, category: CaseCategory) -> Optional[DriftResult]:
        """
        Detect drift for a single category.
        Returns None if the category has no data at all.
        """
        thresholds = self._config.thresholds_for(category)
        tw = self._config.time_window

        if tw.use_time_windows:
            baseline_decisions = self._store.get_baseline_window(
                category,
                tw.baseline_lookback_days,
                tw.baseline_exclusion_hours,
            )
            recent_decisions = self._store.get_detection_window(
                category,
                tw.detection_hours,
            )
        else:
            baseline_decisions = self._store.get_baseline_decisions(
                category, self._config.baseline_window
            )
            recent_decisions = self._store.get_recent_decisions(
                category, self._config.detection_window
            )

        if not baseline_decisions and not recent_decisions:
            return None

        result = DriftResult(
            timestamp=datetime.utcnow(),
            category=category,
        )

        if len(baseline_decisions) < thresholds.min_baseline_size:
            result.insufficient_data = True
            result.insufficient_data_reason = (
                f"Baseline has only {len(baseline_decisions)} decisions "
                f"(need {thresholds.min_baseline_size})"
            )
            return result

        if len(recent_decisions) < thresholds.min_detection_size:
            result.insufficient_data = True
            result.insufficient_data_reason = (
                f"Detection window has only {len(recent_decisions)} decisions "
                f"(need {thresholds.min_detection_size})"
            )
            return result

        baseline_stats = CategoryStats.from_decisions(category, baseline_decisions)
        recent_stats = CategoryStats.from_decisions(category, recent_decisions)
        result.baseline_stats = baseline_stats
        result.recent_stats = recent_stats

        metric_drifts = []

        # Resolution rate drift (proportion test)
        metric_drifts.append(
            self._proportion_drift(
                name="resolution_rate",
                baseline_count=baseline_stats.resolved_count,
                baseline_n=baseline_stats.sample_size,
                recent_count=recent_stats.resolved_count,
                recent_n=recent_stats.sample_size,
                baseline_rate=baseline_stats.resolution_rate,
                recent_rate=recent_stats.resolution_rate,
            )
        )

        # Error rate drift
        metric_drifts.append(
            self._proportion_drift(
                name="error_rate",
                baseline_count=baseline_stats.error_count,
                baseline_n=baseline_stats.sample_size,
                recent_count=recent_stats.error_count,
                recent_n=recent_stats.sample_size,
                baseline_rate=baseline_stats.error_rate,
                recent_rate=recent_stats.error_rate,
            )
        )

        # Escalation rate drift
        metric_drifts.append(
            self._proportion_drift(
                name="escalation_rate",
                baseline_count=baseline_stats.escalation_count,
                baseline_n=baseline_stats.sample_size,
                recent_count=recent_stats.escalation_count,
                recent_n=recent_stats.sample_size,
                baseline_rate=baseline_stats.escalation_rate,
                recent_rate=recent_stats.escalation_rate,
            )
        )

        # Confidence score drift (continuous)
        metric_drifts.append(
            self._continuous_drift(
                name="mean_confidence",
                baseline_values=[d.confidence for d in baseline_decisions],
                recent_values=[d.confidence for d in recent_decisions],
            )
        )

        result.metric_drifts = metric_drifts

        # Composite drift score: weighted average with higher weight on error_rate
        weights = {
            "resolution_rate": 0.30,
            "error_rate": 0.40,
            "escalation_rate": 0.20,
            "mean_confidence": 0.10,
        }
        category_weight = self._config.weight_for(category)
        weighted_sum = sum(
            weights.get(m.metric_name, 0.1) * m.drift_score for m in metric_drifts
        )
        result.drift_score = min(weighted_sum * category_weight, 1.0)

        return result

    # ── Internal metric helpers ────────────────────────────────────────────────

    def _proportion_drift(
        self,
        name: str,
        baseline_count: int,
        baseline_n: int,
        recent_count: int,
        recent_n: int,
        baseline_rate: float,
        recent_rate: float,
    ) -> MetricDrift:
        _, p_value = two_proportion_z_test(baseline_count, baseline_n, recent_count, recent_n)
        h = cohens_h(baseline_rate, recent_rate)
        score = drift_score_from_cohens_h(h)
        abs_change = recent_rate - baseline_rate
        rel_change = (abs_change / baseline_rate * 100.0) if baseline_rate > 0 else 0.0
        return MetricDrift(
            metric_name=name,
            baseline_value=baseline_rate,
            recent_value=recent_rate,
            absolute_change=abs_change,
            relative_change_pct=rel_change,
            effect_size=h,
            p_value=p_value,
            drift_score=score,
        )

    def _continuous_drift(
        self,
        name: str,
        baseline_values: list[float],
        recent_values: list[float],
    ) -> MetricDrift:
        if not baseline_values or not recent_values:
            return MetricDrift(
                metric_name=name,
                baseline_value=0.0, recent_value=0.0,
                absolute_change=0.0, relative_change_pct=0.0,
                effect_size=0.0, p_value=1.0, drift_score=0.0,
            )
        mean1 = sum(baseline_values) / len(baseline_values)
        mean2 = sum(recent_values) / len(recent_values)
        var1 = sample_variance(baseline_values)
        var2 = sample_variance(recent_values)
        _, p_value = welch_t_test(mean1, var1, len(baseline_values), mean2, var2, len(recent_values))
        # Use Cohen's d (standardized mean difference)
        pooled_sd = ((var1 + var2) / 2.0) ** 0.5 if (var1 + var2) > 0 else 1e-9
        cohens_d = abs(mean2 - mean1) / pooled_sd
        score = min(cohens_d / 0.8, 1.0)  # same mapping as Cohen's h
        abs_change = mean2 - mean1
        rel_change = (abs_change / mean1 * 100.0) if mean1 > 0 else 0.0
        return MetricDrift(
            metric_name=name,
            baseline_value=mean1,
            recent_value=mean2,
            absolute_change=abs_change,
            relative_change_pct=rel_change,
            effect_size=cohens_d,
            p_value=p_value,
            drift_score=score,
        )
