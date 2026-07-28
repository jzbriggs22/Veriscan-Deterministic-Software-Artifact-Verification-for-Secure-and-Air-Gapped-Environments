"""
Governance event broker for Server-Sent Events (SSE) streaming.

Publishers (sync scheduler thread) call publish().
Consumers (async FastAPI endpoint) call subscribe() and iterate.

Bridge strategy: loop.call_soon_threadsafe() puts items into per-subscriber
asyncio.Queues from the sync thread without blocking or unsafe cross-thread
coroutine calls.

Event types:
  drift_detected     – emitted after every detection cycle for each category
  alert_fired        – a new DriftAlert was raised
  rollback_triggered – the rollback engine fired
  cycle_complete     – full detection cycle summary
  heartbeat          – keep-alive comment (no event: line, just a comment)
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
from datetime import datetime
from typing import AsyncGenerator, Optional

logger = logging.getLogger(__name__)

_QUEUE_MAXSIZE = 256  # per-subscriber; older events dropped when full


class GovernanceEventBroker:
    """
    Thread-safe fanout broker: one publisher, N async subscribers.

    Each call to subscribe() yields a new independent async stream.
    Slow consumers are protected by the per-queue maxsize — new events are
    silently dropped for a lagging subscriber rather than blocking the publisher.
    """

    def __init__(self) -> None:
        self._subscribers: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = []
        self._lock = threading.Lock()
        self._published_total: int = 0

    # ── Publishing (sync-safe) ─────────────────────────────────────────────────

    def publish(self, event_type: str, payload: dict) -> None:
        """
        Publish an event to all connected SSE subscribers.
        Thread-safe — may be called from any thread including non-async workers.
        Events are dropped for subscribers whose queue is full.
        """
        data = json.dumps(
            {"event": event_type, "timestamp": datetime.utcnow().isoformat(), **payload},
            default=str,
        )
        sse_frame = f"event: {event_type}\ndata: {data}\n\n"

        with self._lock:
            self._published_total += 1
            stale: list[int] = []
            for i, (loop, q) in enumerate(self._subscribers):
                try:
                    loop.call_soon_threadsafe(q.put_nowait, sse_frame)
                except Exception:
                    stale.append(i)
            for i in reversed(stale):
                self._subscribers.pop(i)

    # ── Subscribing (async) ────────────────────────────────────────────────────

    async def subscribe(
        self, heartbeat_seconds: float = 30.0
    ) -> AsyncGenerator[str, None]:
        """
        Async generator that yields SSE-formatted strings.
        Sends a keep-alive comment every heartbeat_seconds to prevent proxy timeouts.
        Automatically deregisters when the client disconnects (generator closed).
        """
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        with self._lock:
            self._subscribers.append((loop, q))
        logger.debug("SSE subscriber connected (total=%d)", self.subscriber_count)
        try:
            while True:
                try:
                    frame = await asyncio.wait_for(q.get(), timeout=heartbeat_seconds)
                    yield frame
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            with self._lock:
                self._subscribers[:] = [
                    (l, qq) for l, qq in self._subscribers if qq is not q
                ]
            logger.debug("SSE subscriber disconnected (total=%d)", self.subscriber_count)

    # ── Introspection ──────────────────────────────────────────────────────────

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    @property
    def published_total(self) -> int:
        return self._published_total


# ── Module-level singleton ─────────────────────────────────────────────────────

_broker: Optional[GovernanceEventBroker] = None
_broker_lock = threading.Lock()


def get_broker() -> GovernanceEventBroker:
    """Return the process-wide event broker (lazy-initialised, thread-safe)."""
    global _broker
    if _broker is None:
        with _broker_lock:
            if _broker is None:
                _broker = GovernanceEventBroker()
    return _broker
