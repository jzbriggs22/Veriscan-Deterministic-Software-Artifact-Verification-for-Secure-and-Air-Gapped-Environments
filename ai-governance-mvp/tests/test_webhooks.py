"""Tests for webhook dispatcher."""
from __future__ import annotations

import http.server
import json
import threading
from datetime import datetime

import pytest

from src.engine.webhooks import WebhookConfig, WebhookDispatcher
from src.governance.schema import AlertSeverity, CaseCategory, DriftAlert, RollbackEvent


# ── Minimal test HTTP server ───────────────────────────────────────────────────

class _CaptureHandler(http.server.BaseHTTPRequestHandler):
    """Captures POST body; stores it on the server."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass  # silence test output


class _FailHandler(http.server.BaseHTTPRequestHandler):
    """Always returns 500."""

    def do_POST(self):
        self.server.hit_count = getattr(self.server, "hit_count", 0) + 1
        self.send_response(500)
        self.end_headers()

    def log_message(self, *args):
        pass


def _start_server(handler_cls) -> tuple[http.server.HTTPServer, str, threading.Thread]:
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    server.received = []
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{port}/", t


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def capture_server():
    server, url, _ = _start_server(_CaptureHandler)
    yield server, url
    server.shutdown()


@pytest.fixture
def fail_server():
    server, url, _ = _start_server(_FailHandler)
    yield server, url
    server.shutdown()


def _make_alert(severity: AlertSeverity = AlertSeverity.CRITICAL) -> DriftAlert:
    return DriftAlert(
        severity=severity,
        category=CaseCategory.BILLING_DISPUTE,
        message="Billing dispute drift detected",
        drift_score=0.88,
        details={"resolution_rate_drop": 0.43},
    )


def _make_rollback() -> RollbackEvent:
    return RollbackEvent(
        reason="Critical drift on fraud_claim",
        triggered_by="DriftDetector",
        category=CaseCategory.FRAUD_CLAIM,
        drift_score=0.92,
    )


# ── Generic webhook ────────────────────────────────────────────────────────────

def test_dispatch_alert_sends_generic_payload(capture_server):
    server, url = capture_server
    cfg = WebhookConfig(url=url, format="generic", retry_attempts=1)
    dispatcher = WebhookDispatcher([cfg])
    results = dispatcher.dispatch_alert(_make_alert())

    assert results[url] is True
    assert len(server.received) == 1
    payload = server.received[0]
    assert payload["event_type"] == "governance_alert"
    assert payload["severity"] == "critical"
    assert payload["category"] == "billing_dispute"
    assert payload["drift_score"] == pytest.approx(0.88, abs=1e-6)


def test_dispatch_rollback_sends_generic_payload(capture_server):
    server, url = capture_server
    cfg = WebhookConfig(url=url, format="generic", retry_attempts=1)
    dispatcher = WebhookDispatcher([cfg])
    results = dispatcher.dispatch_rollback(_make_rollback())

    assert results[url] is True
    assert len(server.received) == 1
    payload = server.received[0]
    assert payload["event_type"] == "governance_rollback"
    assert payload["category"] == "fraud_claim"


# ── Slack webhook ──────────────────────────────────────────────────────────────

def test_dispatch_alert_sends_slack_payload(capture_server):
    server, url = capture_server
    cfg = WebhookConfig(url=url, format="slack", retry_attempts=1)
    dispatcher = WebhookDispatcher([cfg])
    results = dispatcher.dispatch_alert(_make_alert())

    assert results[url] is True
    payload = server.received[0]
    assert "text" in payload
    assert "CRITICAL" in payload["text"]
    assert "billing_dispute" in payload["text"]


def test_dispatch_rollback_slack_payload_mentions_rollback(capture_server):
    server, url = capture_server
    cfg = WebhookConfig(url=url, format="slack", retry_attempts=1)
    dispatcher = WebhookDispatcher([cfg])
    dispatcher.dispatch_rollback(_make_rollback())

    payload = server.received[0]
    assert "ROLLBACK" in payload["text"]
    assert "fraud_claim" in payload["text"]


# ── Severity filtering ─────────────────────────────────────────────────────────

def test_severity_filter_blocks_warning_when_critical_required(capture_server):
    server, url = capture_server
    cfg = WebhookConfig(url=url, format="generic", min_severity="critical", retry_attempts=1)
    dispatcher = WebhookDispatcher([cfg])

    warning_alert = _make_alert(severity=AlertSeverity.WARNING)
    results = dispatcher.dispatch_alert(warning_alert)
    # No request should have been sent
    assert url not in results
    assert len(server.received) == 0


def test_severity_filter_allows_critical_when_warning_required(capture_server):
    server, url = capture_server
    cfg = WebhookConfig(url=url, format="generic", min_severity="warning", retry_attempts=1)
    dispatcher = WebhookDispatcher([cfg])
    results = dispatcher.dispatch_alert(_make_alert(AlertSeverity.CRITICAL))
    assert results[url] is True


def test_severity_filter_allows_warning_when_warning_required(capture_server):
    server, url = capture_server
    cfg = WebhookConfig(url=url, format="generic", min_severity="warning", retry_attempts=1)
    dispatcher = WebhookDispatcher([cfg])
    results = dispatcher.dispatch_alert(_make_alert(AlertSeverity.WARNING))
    assert results[url] is True


# ── Custom header ──────────────────────────────────────────────────────────────

def test_secret_header_is_sent(capture_server):
    """Verify that secret_header is forwarded in the HTTP request."""
    server, url = capture_server
    cfg = WebhookConfig(
        url=url, format="generic", retry_attempts=1,
        secret_header="X-Governance-Secret: test-token-123",
    )

    class _HeaderCapture(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.server.headers_received = dict(self.headers)
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    hdr_server, hdr_url, _ = _start_server(_HeaderCapture)
    hdr_server.headers_received = {}
    try:
        cfg2 = WebhookConfig(url=hdr_url, format="generic", retry_attempts=1,
                             secret_header="X-Governance-Secret: test-token-123")
        WebhookDispatcher([cfg2]).dispatch_alert(_make_alert())
        # HTTP headers are case-insensitive; search without assuming casing
        hdrs_lower = {k.lower(): v for k, v in hdr_server.headers_received.items()}
        assert hdrs_lower.get("x-governance-secret") == "test-token-123"
    finally:
        hdr_server.shutdown()


# ── Retry behaviour ────────────────────────────────────────────────────────────

def test_failed_server_returns_false(fail_server):
    _, url = fail_server
    cfg = WebhookConfig(url=url, format="generic", retry_attempts=2, timeout_seconds=2.0)
    dispatcher = WebhookDispatcher([cfg])
    results = dispatcher.dispatch_alert(_make_alert())
    assert results[url] is False


def test_multiple_webhooks_dispatched_independently(capture_server):
    server, url = capture_server
    cfg1 = WebhookConfig(url=url, format="generic", retry_attempts=1)
    cfg2 = WebhookConfig(url=url, format="slack", retry_attempts=1)
    dispatcher = WebhookDispatcher([cfg1, cfg2])
    # Two configs pointing at same capture server — both succeed
    results = dispatcher.dispatch_alert(_make_alert())
    assert len(server.received) == 2


def test_no_webhooks_configured_returns_empty(capture_server):
    dispatcher = WebhookDispatcher([])
    results = dispatcher.dispatch_alert(_make_alert())
    assert results == {}
