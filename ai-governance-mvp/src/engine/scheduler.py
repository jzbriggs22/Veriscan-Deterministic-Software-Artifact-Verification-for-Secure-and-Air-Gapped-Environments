"""Background detection scheduler: periodically runs drift detection and fires webhooks."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Callable, Optional

from ..detection.detector import DriftDetector
from ..engine.alerts import AlertEngine
from ..engine.events import GovernanceEventBroker
from ..engine.rollback import RollbackEngine
from ..engine.webhooks import WebhookDispatcher
from ..ingestion.store import DecisionStore

logger = logging.getLogger(__name__)


class DetectionScheduler:
    """
    Runs drift detection on a fixed interval in a background daemon thread.

    Each cycle:
      1. Run detection across all monitored categories
      2. Process results → generate new alerts
      3. Evaluate rollback rules → trigger rollback if conditions met
      4. Persist all drift results to drift_history
      5. Dispatch webhooks for new alerts and rollback events

    Thread-safe: start/stop can be called from any thread.
    Fail-safe: exceptions in a detection cycle are logged and swallowed so the
    scheduler keeps running (a broken detection cycle must not kill the server).
    """

    def __init__(
        self,
        store: DecisionStore,
        detector: DriftDetector,
        alert_engine: AlertEngine,
        rollback_engine: RollbackEngine,
        dispatcher: Optional[WebhookDispatcher] = None,
        on_cycle: Optional[Callable[[list], None]] = None,
        event_broker: Optional[GovernanceEventBroker] = None,
    ) -> None:
        self._store = store
        self._detector = detector
        self._alert_engine = alert_engine
        self._rollback_engine = rollback_engine
        self._dispatcher = dispatcher
        self._on_cycle = on_cycle  # optional hook for tests / external observers
        self._event_broker = event_broker  # SSE broker; None = SSE disabled

        self._interval_seconds: float = 300.0
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self.cycle_count: int = 0
        self.last_run_at: Optional[datetime] = None
        self.last_error: Optional[str] = None

    def start(self, interval_seconds: float = 300.0) -> None:
        """Start the background scheduler. No-op if already running."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._interval_seconds = interval_seconds
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name="governance-scheduler",
                daemon=True,
            )
            self._thread.start()
            logger.info("DetectionScheduler started (interval=%.0fs)", interval_seconds)

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the scheduler to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        logger.info("DetectionScheduler stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def run_now(self) -> list:
        """Run a single detection cycle synchronously (useful for tests and one-shots)."""
        return self._run_cycle()

    # ── Internal ───────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            self._run_cycle()
            # Use wait() so stop() wakes us immediately instead of sleeping the full interval
            self._stop_event.wait(timeout=self._interval_seconds)

    def _run_cycle(self) -> list:
        try:
            drift_results = self._detector.run_detection()
            new_alerts = self._alert_engine.process_drift_results(drift_results)
            rollback_event = self._rollback_engine.maybe_trigger(drift_results)

            # Persist drift history
            self._store.store_drift_results_batch(drift_results)

            # Dispatch webhooks for new alerts
            if self._dispatcher and new_alerts:
                for alert in new_alerts:
                    try:
                        self._dispatcher.dispatch_alert(alert)
                    except Exception as exc:
                        logger.warning("Webhook dispatch failed for alert %s: %s", alert.alert_id, exc)

            # Dispatch webhook for rollback
            if self._dispatcher and rollback_event:
                try:
                    self._dispatcher.dispatch_rollback(rollback_event)
                except Exception as exc:
                    logger.warning("Webhook dispatch failed for rollback %s: %s", rollback_event.event_id, exc)

            self.cycle_count += 1
            self.last_run_at = datetime.utcnow()
            self.last_error = None

            # Publish SSE events
            if self._event_broker:
                for r in drift_results:
                    if not r.insufficient_data:
                        self._event_broker.publish("drift_detected", {
                            "category": r.category.value,
                            "drift_score": round(r.drift_score, 4),
                            "insufficient_data": r.insufficient_data,
                        })
                for alert in new_alerts:
                    self._event_broker.publish("alert_fired", {
                        "alert_id": alert.alert_id,
                        "severity": alert.severity.value,
                        "category": alert.category.value,
                        "message": alert.message,
                        "drift_score": round(alert.drift_score, 4),
                    })
                if rollback_event:
                    self._event_broker.publish("rollback_triggered", {
                        "event_id": rollback_event.event_id,
                        "reason": rollback_event.reason,
                        "category": rollback_event.category.value if rollback_event.category else None,
                        "drift_score": round(rollback_event.drift_score, 4),
                    })
                self._event_broker.publish("cycle_complete", {
                    "cycle": self.cycle_count,
                    "categories_checked": len(drift_results),
                    "new_alerts": len(new_alerts),
                    "rollback_triggered": rollback_event is not None,
                })

            if self._on_cycle:
                try:
                    self._on_cycle(drift_results)
                except Exception:
                    pass

            logger.debug(
                "Detection cycle %d: %d results, %d new alerts, rollback=%s",
                self.cycle_count,
                len(drift_results),
                len(new_alerts),
                rollback_event is not None,
            )
            return drift_results

        except Exception as exc:
            self.last_error = str(exc)
            logger.exception("Detection cycle failed: %s", exc)
            return []
