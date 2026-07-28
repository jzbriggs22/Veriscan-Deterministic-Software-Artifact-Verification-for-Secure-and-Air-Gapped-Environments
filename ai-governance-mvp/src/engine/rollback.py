"""Rollback engine: evaluates governance thresholds and triggers rollback."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from ..governance.config import GovernanceConfig
from ..governance.schema import DriftResult, RollbackEvent
from ..ingestion.store import DecisionStore


class RollbackEngine:
    """
    Evaluates drift results against rollback rules and manages rollback state.
    Rollback is fail-closed: a rule failure does not prevent triggering.
    """

    def __init__(self, store: DecisionStore, config: GovernanceConfig) -> None:
        self._store = store
        self._config = config

    def evaluate(
        self, drift_results: list[DriftResult]
    ) -> tuple[bool, Optional[str], Optional[DriftResult]]:
        """
        Evaluate rollback rules against drift results.
        Returns (should_rollback, reason, triggering_drift_result).
        Rules are evaluated in config order; first match wins.
        """
        # Only high-risk categories trigger rollback by default
        high_risk_results = [r for r in drift_results if r.is_high_risk and not r.insufficient_data]

        for result in high_risk_results:
            recent_error_rate = (
                result.recent_stats.error_rate if result.recent_stats else 0.0
            )
            for rule in self._config.rollback_rules:
                if rule.matches(
                    drift_score=result.drift_score,
                    error_rate=recent_error_rate,
                    category=result.category,
                    is_high_risk=result.is_high_risk,
                ):
                    reason = (
                        f"{rule.description} — "
                        f"category={result.category.value}, "
                        f"drift_score={result.drift_score:.3f}, "
                        f"error_rate={recent_error_rate:.1%}"
                    )
                    return True, reason, result

        return False, None, None

    def trigger_rollback(
        self, reason: str, drift_result: Optional[DriftResult] = None
    ) -> RollbackEvent:
        """
        Persist a rollback event and return it.
        Does NOT stop the agent — the caller (orchestrator) must do that.
        """
        event = RollbackEvent(
            timestamp=datetime.utcnow(),
            reason=reason,
            triggered_by="governance_engine",
            category=drift_result.category if drift_result else None,
            drift_score=drift_result.drift_score if drift_result else 0.0,
        )
        self._store.store_rollback_event(event)
        return event

    def maybe_trigger(
        self, drift_results: list[DriftResult]
    ) -> Optional[RollbackEvent]:
        """
        Convenience: evaluate + trigger if conditions are met.
        Returns the RollbackEvent if triggered, else None.
        Skips if a rollback is already active.
        """
        if self.is_rollback_active():
            return None

        should_rollback, reason, triggering = self.evaluate(drift_results)
        if should_rollback and reason:
            return self.trigger_rollback(reason, triggering)
        return None

    def is_rollback_active(self) -> bool:
        return self._store.get_active_rollback() is not None

    def resolve_rollback(self, resolution_note: str) -> bool:
        active = self._store.get_active_rollback()
        if active is None:
            return False
        return self._store.resolve_rollback(active.event_id, resolution_note)

    def get_rollback_history(self) -> list[RollbackEvent]:
        return self._store.get_rollback_events()
