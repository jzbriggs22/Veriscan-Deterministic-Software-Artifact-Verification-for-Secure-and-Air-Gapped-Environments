"""SQLite-backed decision store with thread-safe access."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional

from ..governance.schema import (
    AgentDecision,
    AlertSeverity,
    CaseCategory,
    DecisionOutcome,
    DriftAlert,
    RollbackEvent,
)

_DDL = """
CREATE TABLE IF NOT EXISTS decisions (
    decision_id        TEXT PRIMARY KEY,
    case_id            TEXT NOT NULL,
    category           TEXT NOT NULL,
    outcome            TEXT NOT NULL,
    confidence         REAL NOT NULL,
    timestamp          TEXT NOT NULL,
    agent_version      TEXT NOT NULL,
    processing_time_ms REAL NOT NULL,
    case_text          TEXT DEFAULT '',
    metadata_json      TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_decisions_category_ts
    ON decisions (category, timestamp);
CREATE INDEX IF NOT EXISTS idx_decisions_ts
    ON decisions (timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id           TEXT PRIMARY KEY,
    timestamp          TEXT NOT NULL,
    severity           TEXT NOT NULL,
    category           TEXT NOT NULL,
    message            TEXT NOT NULL,
    drift_score        REAL DEFAULT 0.0,
    details_json       TEXT DEFAULT '{}',
    acknowledged_at    TEXT,
    rollback_event_id  TEXT
);

CREATE TABLE IF NOT EXISTS rollback_events (
    event_id           TEXT PRIMARY KEY,
    timestamp          TEXT NOT NULL,
    reason             TEXT NOT NULL,
    triggered_by       TEXT NOT NULL,
    category           TEXT,
    drift_score        REAL DEFAULT 0.0,
    agent_version      TEXT DEFAULT '',
    resolved_at        TEXT,
    resolution_note    TEXT DEFAULT ''
);
"""


class DecisionStore:
    """Thread-safe SQLite store for agent decisions, alerts, and rollback events.

    Uses a single persistent connection protected by a mutex so that in-memory
    databases (shared across all operations in a process) work correctly.
    File-based databases gain the same thread safety at the cost of concurrency
    (acceptable for the governance use-case where writes are infrequent).
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        # Persistent connection — essential for :memory: databases
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_DDL)
        self._conn.commit()

    @contextmanager
    def _cursor(self) -> Generator[tuple[sqlite3.Connection, sqlite3.Cursor], None, None]:
        with self._lock:
            try:
                cur = self._conn.cursor()
                yield self._conn, cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ── Decisions ──────────────────────────────────────────────────────────────

    def store_decision(self, decision: AgentDecision) -> None:
        with self._cursor() as (conn, cur):
            cur.execute(
                """INSERT OR REPLACE INTO decisions
                   (decision_id, case_id, category, outcome, confidence,
                    timestamp, agent_version, processing_time_ms, case_text, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision.decision_id,
                    decision.case_id,
                    decision.category.value,
                    decision.outcome.value,
                    decision.confidence,
                    decision.timestamp.isoformat(),
                    decision.agent_version,
                    decision.processing_time_ms,
                    decision.case_text,
                    json.dumps(decision.metadata),
                ),
            )

    def store_decisions_batch(self, decisions: list[AgentDecision]) -> None:
        with self._cursor() as (conn, cur):
            cur.executemany(
                """INSERT OR REPLACE INTO decisions
                   (decision_id, case_id, category, outcome, confidence,
                    timestamp, agent_version, processing_time_ms, case_text, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        d.decision_id,
                        d.case_id,
                        d.category.value,
                        d.outcome.value,
                        d.confidence,
                        d.timestamp.isoformat(),
                        d.agent_version,
                        d.processing_time_ms,
                        d.case_text,
                        json.dumps(d.metadata),
                    )
                    for d in decisions
                ],
            )

    def get_baseline_decisions(
        self, category: CaseCategory, limit: int
    ) -> list[AgentDecision]:
        """Return the oldest `limit` decisions for `category` (establishes baseline)."""
        with self._cursor() as (conn, cur):
            cur.execute(
                """SELECT * FROM decisions
                   WHERE category = ?
                   ORDER BY timestamp ASC
                   LIMIT ?""",
                (category.value, limit),
            )
            return [_row_to_decision(r) for r in cur.fetchall()]

    def get_recent_decisions(
        self, category: CaseCategory, limit: int
    ) -> list[AgentDecision]:
        """Return the most recent `limit` decisions for `category`."""
        with self._cursor() as (conn, cur):
            cur.execute(
                """SELECT * FROM decisions
                   WHERE category = ?
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (category.value, limit),
            )
            return [_row_to_decision(r) for r in cur.fetchall()]

    def get_all_recent(self, limit: int = 200) -> list[AgentDecision]:
        with self._cursor() as (conn, cur):
            cur.execute(
                "SELECT * FROM decisions ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            return [_row_to_decision(r) for r in cur.fetchall()]

    def count_by_category(self) -> dict[str, int]:
        with self._cursor() as (conn, cur):
            cur.execute("SELECT category, COUNT(*) as cnt FROM decisions GROUP BY category")
            return {r["category"]: r["cnt"] for r in cur.fetchall()}

    def total_count(self) -> int:
        with self._cursor() as (conn, cur):
            cur.execute("SELECT COUNT(*) FROM decisions")
            row = cur.fetchone()
            return row[0] if row else 0

    def get_decisions_in_window(
        self,
        category: CaseCategory,
        start: datetime,
        end: datetime,
    ) -> list[AgentDecision]:
        """Return all decisions for `category` with timestamp in [start, end)."""
        with self._cursor() as (conn, cur):
            cur.execute(
                """SELECT * FROM decisions
                   WHERE category = ?
                     AND timestamp >= ?
                     AND timestamp < ?
                   ORDER BY timestamp ASC""",
                (category.value, start.isoformat(), end.isoformat()),
            )
            return [_row_to_decision(r) for r in cur.fetchall()]

    def get_baseline_window(
        self,
        category: CaseCategory,
        baseline_lookback_days: int,
        baseline_exclusion_hours: int,
    ) -> list[AgentDecision]:
        """
        Return decisions for the baseline period.

        The baseline window is the period from `baseline_lookback_days` ago to
        `baseline_exclusion_hours` ago.  The exclusion gap prevents the most-recent
        data (which may be drifted) from contaminating the baseline.

        Example with defaults (lookback=30d, exclusion=168h/7d):
          baseline covers: [now-30d, now-7d)
          detection covers: [now-24h, now)
          gap between them: 6 days — avoids overlap
        """
        now = datetime.utcnow()
        end = now - timedelta(hours=baseline_exclusion_hours)
        start = now - timedelta(days=baseline_lookback_days)
        return self.get_decisions_in_window(category, start, end)

    def get_detection_window(
        self,
        category: CaseCategory,
        detection_hours: int,
    ) -> list[AgentDecision]:
        """Return decisions in the most-recent `detection_hours` window."""
        now = datetime.utcnow()
        start = now - timedelta(hours=detection_hours)
        return self.get_decisions_in_window(category, start, now)

    def get_decisions_since(self, since: datetime) -> list[AgentDecision]:
        """Return all decisions (any category) after `since`, oldest first."""
        with self._cursor() as (conn, cur):
            cur.execute(
                "SELECT * FROM decisions WHERE timestamp >= ? ORDER BY timestamp ASC",
                (since.isoformat(),),
            )
            return [_row_to_decision(r) for r in cur.fetchall()]

    def oldest_decision_time(self, category: Optional[CaseCategory] = None) -> Optional[datetime]:
        """Return the timestamp of the oldest stored decision, optionally filtered by category."""
        with self._cursor() as (conn, cur):
            if category:
                cur.execute(
                    "SELECT MIN(timestamp) FROM decisions WHERE category = ?",
                    (category.value,),
                )
            else:
                cur.execute("SELECT MIN(timestamp) FROM decisions")
            row = cur.fetchone()
            raw = row[0] if row else None
            return datetime.fromisoformat(raw) if raw else None

    # ── Normal metrics ─────────────────────────────────────────────────────────

    def get_normal_metrics_window(self, limit: int = 200) -> list[AgentDecision]:
        return self.get_all_recent(limit)

    # ── Alerts ─────────────────────────────────────────────────────────────────

    def store_alert(self, alert: DriftAlert) -> None:
        with self._cursor() as (conn, cur):
            cur.execute(
                """INSERT OR REPLACE INTO alerts
                   (alert_id, timestamp, severity, category, message,
                    drift_score, details_json, acknowledged_at, rollback_event_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert.alert_id,
                    alert.timestamp.isoformat(),
                    alert.severity.value,
                    alert.category.value,
                    alert.message,
                    alert.drift_score,
                    json.dumps(alert.details),
                    alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                    alert.rollback_event_id,
                ),
            )

    def get_active_alerts(self) -> list[DriftAlert]:
        with self._cursor() as (conn, cur):
            cur.execute(
                "SELECT * FROM alerts WHERE acknowledged_at IS NULL ORDER BY timestamp DESC"
            )
            return [_row_to_alert(r) for r in cur.fetchall()]

    def get_all_alerts(self, limit: int = 50) -> list[DriftAlert]:
        with self._cursor() as (conn, cur):
            cur.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            return [_row_to_alert(r) for r in cur.fetchall()]

    def acknowledge_alert(self, alert_id: str) -> bool:
        with self._cursor() as (conn, cur):
            cur.execute(
                "UPDATE alerts SET acknowledged_at = ? WHERE alert_id = ?",
                (datetime.utcnow().isoformat(), alert_id),
            )
            return cur.rowcount > 0

    # ── Rollback events ────────────────────────────────────────────────────────

    def store_rollback_event(self, event: RollbackEvent) -> None:
        with self._cursor() as (conn, cur):
            cur.execute(
                """INSERT OR REPLACE INTO rollback_events
                   (event_id, timestamp, reason, triggered_by, category,
                    drift_score, agent_version, resolved_at, resolution_note)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.reason,
                    event.triggered_by,
                    event.category.value if event.category else None,
                    event.drift_score,
                    event.agent_version,
                    event.resolved_at.isoformat() if event.resolved_at else None,
                    event.resolution_note,
                ),
            )

    def get_rollback_events(self, limit: int = 20) -> list[RollbackEvent]:
        with self._cursor() as (conn, cur):
            cur.execute(
                "SELECT * FROM rollback_events ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            return [_row_to_rollback(r) for r in cur.fetchall()]

    def get_active_rollback(self) -> Optional[RollbackEvent]:
        with self._cursor() as (conn, cur):
            cur.execute(
                "SELECT * FROM rollback_events WHERE resolved_at IS NULL ORDER BY timestamp DESC LIMIT 1"
            )
            row = cur.fetchone()
            return _row_to_rollback(row) if row else None

    def resolve_rollback(self, event_id: str, note: str) -> bool:
        with self._cursor() as (conn, cur):
            cur.execute(
                "UPDATE rollback_events SET resolved_at = ?, resolution_note = ? WHERE event_id = ?",
                (datetime.utcnow().isoformat(), note, event_id),
            )
            return cur.rowcount > 0


# ── Row deserializers ──────────────────────────────────────────────────────────

def _row_to_decision(row: sqlite3.Row) -> AgentDecision:
    return AgentDecision(
        decision_id=row["decision_id"],
        case_id=row["case_id"],
        category=CaseCategory(row["category"]),
        outcome=DecisionOutcome(row["outcome"]),
        confidence=row["confidence"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        agent_version=row["agent_version"],
        processing_time_ms=row["processing_time_ms"],
        case_text=row["case_text"] or "",
        metadata=json.loads(row["metadata_json"] or "{}"),
    )


def _row_to_alert(row: sqlite3.Row) -> DriftAlert:
    return DriftAlert(
        alert_id=row["alert_id"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        severity=AlertSeverity(row["severity"]),
        category=CaseCategory(row["category"]),
        message=row["message"],
        drift_score=row["drift_score"] or 0.0,
        details=json.loads(row["details_json"] or "{}"),
        acknowledged_at=(
            datetime.fromisoformat(row["acknowledged_at"])
            if row["acknowledged_at"]
            else None
        ),
        rollback_event_id=row["rollback_event_id"],
    )


def _row_to_rollback(row: sqlite3.Row) -> RollbackEvent:
    return RollbackEvent(
        event_id=row["event_id"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        reason=row["reason"],
        triggered_by=row["triggered_by"],
        category=CaseCategory(row["category"]) if row["category"] else None,
        drift_score=row["drift_score"] or 0.0,
        agent_version=row["agent_version"] or "",
        resolved_at=(
            datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None
        ),
        resolution_note=row["resolution_note"] or "",
    )
