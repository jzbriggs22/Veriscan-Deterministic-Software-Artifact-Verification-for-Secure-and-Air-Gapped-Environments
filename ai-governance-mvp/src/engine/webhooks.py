"""Webhook dispatcher: sends governance alerts to Slack and generic HTTP endpoints."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Literal, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..governance.schema import DriftAlert, RollbackEvent

logger = logging.getLogger(__name__)


@dataclass
class WebhookConfig:
    """Configuration for a single webhook destination."""
    url: str
    format: Literal["slack", "generic"] = "generic"
    secret_header: Optional[str] = None    # e.g. "X-Governance-Secret: <token>"
    retry_attempts: int = 3
    timeout_seconds: float = 10.0
    min_severity: str = "warning"          # "warning" | "critical" — filter by severity


def _slack_payload(alert: DriftAlert) -> dict:
    severity_emoji = ":rotating_light:" if alert.severity.value == "critical" else ":warning:"
    return {
        "text": (
            f"{severity_emoji} *[{alert.severity.value.upper()}] AI Governance Alert*\n"
            f"Category: `{alert.category.value}`\n"
            f"Message: {alert.message}\n"
            f"Drift score: `{alert.drift_score:.3f}`"
        )
    }


def _slack_rollback_payload(event: RollbackEvent) -> dict:
    return {
        "text": (
            f":rotating_light: *ROLLBACK TRIGGERED*\n"
            f"Reason: {event.reason}\n"
            f"Category: `{event.category.value if event.category else 'multiple'}`\n"
            f"Drift score: `{event.drift_score:.3f}`\n"
            f"Event ID: `{event.event_id}`"
        )
    }


def _generic_alert_payload(alert: DriftAlert) -> dict:
    return {
        "event_type": "governance_alert",
        "alert_id": alert.alert_id,
        "severity": alert.severity.value,
        "category": alert.category.value,
        "message": alert.message,
        "drift_score": alert.drift_score,
        "timestamp": alert.timestamp.isoformat(),
        "details": alert.details,
    }


def _generic_rollback_payload(event: RollbackEvent) -> dict:
    return {
        "event_type": "governance_rollback",
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "reason": event.reason,
        "triggered_by": event.triggered_by,
        "category": event.category.value if event.category else None,
        "drift_score": event.drift_score,
    }


class WebhookDispatcher:
    """
    Dispatches governance alerts and rollback events to configured webhook endpoints.

    Uses stdlib urllib (no external HTTP dependencies) with synchronous delivery
    and exponential backoff on transient failures.
    """

    def __init__(self, configs: list[WebhookConfig]) -> None:
        self._configs = configs

    def dispatch_alert(self, alert: DriftAlert) -> dict[str, bool]:
        """
        Send an alert to all configured webhooks that match its severity.
        Returns a dict mapping webhook URL → success bool.
        """
        results: dict[str, bool] = {}
        for cfg in self._configs:
            if not self._severity_matches(alert.severity.value, cfg.min_severity):
                continue
            if cfg.format == "slack":
                payload = _slack_payload(alert)
            else:
                payload = _generic_alert_payload(alert)
            results[cfg.url] = self._send(cfg, payload)
        return results

    def dispatch_rollback(self, event: RollbackEvent) -> dict[str, bool]:
        """Send a rollback event notification to all configured webhooks."""
        results: dict[str, bool] = {}
        for cfg in self._configs:
            if cfg.format == "slack":
                payload = _slack_rollback_payload(event)
            else:
                payload = _generic_rollback_payload(event)
            results[cfg.url] = self._send(cfg, payload)
        return results

    # ── Internal ───────────────────────────────────────────────────────────────

    @staticmethod
    def _severity_matches(alert_severity: str, min_severity: str) -> bool:
        order = {"info": 0, "warning": 1, "critical": 2}
        return order.get(alert_severity, 0) >= order.get(min_severity, 0)

    def _send(self, cfg: WebhookConfig, payload: dict) -> bool:
        """POST payload as JSON with retry + exponential backoff. Returns True on success."""
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if cfg.secret_header:
            k, _, v = cfg.secret_header.partition(":")
            headers[k.strip()] = v.strip()

        delay = 1.0
        for attempt in range(1, cfg.retry_attempts + 1):
            try:
                req = Request(cfg.url, data=body, headers=headers, method="POST")
                with urlopen(req, timeout=cfg.timeout_seconds) as resp:
                    if 200 <= resp.status < 300:
                        return True
                    logger.warning(
                        "Webhook %s returned HTTP %d on attempt %d",
                        cfg.url, resp.status, attempt,
                    )
            except HTTPError as exc:
                logger.warning("Webhook %s HTTP error %d on attempt %d", cfg.url, exc.code, attempt)
            except URLError as exc:
                logger.warning("Webhook %s URL error on attempt %d: %s", cfg.url, attempt, exc.reason)
            except Exception as exc:
                logger.warning("Webhook %s unexpected error on attempt %d: %s", cfg.url, attempt, exc)

            if attempt < cfg.retry_attempts:
                time.sleep(delay)
                delay *= 2.0

        logger.error("Webhook %s failed after %d attempts", cfg.url, cfg.retry_attempts)
        return False
