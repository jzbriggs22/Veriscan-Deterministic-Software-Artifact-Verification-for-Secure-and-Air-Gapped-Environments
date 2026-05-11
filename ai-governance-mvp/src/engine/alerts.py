"""Alert engine: converts drift results into actionable alerts."""
from __future__ import annotations

from datetime import datetime

from ..governance.config import GovernanceConfig
from ..governance.schema import AlertSeverity, DriftAlert, DriftResult
from ..ingestion.store import DecisionStore


class AlertEngine:
    """Generates, deduplicates, and stores DriftAlerts from DriftResults."""

    def __init__(self, store: DecisionStore, config: GovernanceConfig) -> None:
        self._store = store
        self._config = config

    def process_drift_results(self, results: list[DriftResult]) -> list[DriftAlert]:
        """
        Evaluate each DriftResult and emit alerts for any that exceed thresholds.
        Alerts are persisted to the store. Returns only newly generated alerts.
        """
        new_alerts: list[DriftAlert] = []
        for result in results:
            if result.insufficient_data:
                continue
            alert = self._maybe_create_alert(result)
            if alert is not None:
                self._store.store_alert(alert)
                new_alerts.append(alert)
        return new_alerts

    def _maybe_create_alert(self, result: DriftResult) -> DriftAlert | None:
        thresholds = self._config.thresholds_for(result.category)

        # Absolute error-rate ceiling takes priority over score thresholds
        recent_error_rate = (
            result.recent_stats.error_rate if result.recent_stats else 0.0
        )
        if recent_error_rate > thresholds.max_error_rate and result.is_high_risk:
            return self._build_alert(
                result=result,
                severity=AlertSeverity.CRITICAL,
                reason=(
                    f"Error rate {recent_error_rate:.1%} exceeds ceiling "
                    f"{thresholds.max_error_rate:.1%} for high-risk category"
                ),
            )

        if result.drift_score >= thresholds.critical_score:
            return self._build_alert(
                result=result,
                severity=AlertSeverity.CRITICAL,
                reason=f"Drift score {result.drift_score:.2f} ≥ critical threshold {thresholds.critical_score:.2f}",
            )

        if result.drift_score >= thresholds.warning_score:
            return self._build_alert(
                result=result,
                severity=AlertSeverity.WARNING,
                reason=f"Drift score {result.drift_score:.2f} ≥ warning threshold {thresholds.warning_score:.2f}",
            )

        return None

    def _build_alert(
        self, result: DriftResult, severity: AlertSeverity, reason: str
    ) -> DriftAlert:
        worst = result.worst_metric()
        details: dict = {
            "reason": reason,
            "drift_score": result.drift_score,
            "category": result.category.value,
            "is_high_risk": result.is_high_risk,
        }
        if result.baseline_stats and result.recent_stats:
            details["baseline_resolution_rate"] = round(result.baseline_stats.resolution_rate, 4)
            details["recent_resolution_rate"] = round(result.recent_stats.resolution_rate, 4)
            details["baseline_error_rate"] = round(result.baseline_stats.error_rate, 4)
            details["recent_error_rate"] = round(result.recent_stats.error_rate, 4)
            details["baseline_sample_size"] = result.baseline_stats.sample_size
            details["recent_sample_size"] = result.recent_stats.sample_size
        if worst:
            details["worst_metric"] = {
                "name": worst.metric_name,
                "baseline": round(worst.baseline_value, 4),
                "recent": round(worst.recent_value, 4),
                "change_pct": round(worst.relative_change_pct, 1),
                "effect_size": round(worst.effect_size, 3),
                "p_value": round(worst.p_value, 4),
            }

        category_display = next(
            (h.display_name for h in self._config.high_risk_categories if h.category == result.category),
            result.category.value.replace("_", " ").title(),
        )
        message = (
            f"[{severity.value.upper()}] {category_display}: {reason}"
        )
        if worst and worst.is_significant:
            rel = worst.relative_change_pct
            direction = "▲" if rel > 0 else "▼"
            message += (
                f" | {worst.metric_name} {direction}{abs(rel):.1f}%"
                f" ({worst.baseline_value:.1%}→{worst.recent_value:.1%})"
            )

        return DriftAlert(
            timestamp=datetime.utcnow(),
            severity=severity,
            category=result.category,
            message=message,
            drift_score=result.drift_score,
            details=details,
        )

    def get_active_alerts(self) -> list[DriftAlert]:
        return self._store.get_active_alerts()
