"""Shared pytest fixtures and governance rollback hook."""
from __future__ import annotations

import random
from datetime import datetime, timedelta

import pytest

from src.governance.config import GovernanceConfig
from src.governance.schema import AgentDecision, CaseCategory, DecisionOutcome, RollbackEvent
from src.ingestion.store import DecisionStore

rng = random.Random(0)


def _make_decision(
    case_id: str = "CASE-001",
    category: CaseCategory = CaseCategory.ROUTINE,
    outcome: DecisionOutcome = DecisionOutcome.RESOLVED,
    confidence: float = 0.85,
    ts: datetime | None = None,
    agent_version: str = "v1.0",
    processing_time_ms: float = 500.0,
) -> AgentDecision:
    return AgentDecision(
        case_id=case_id,
        category=category,
        outcome=outcome,
        confidence=confidence,
        timestamp=ts or datetime.utcnow(),
        agent_version=agent_version,
        processing_time_ms=processing_time_ms,
    )


def make_decision_batch(
    category: CaseCategory,
    n: int,
    resolve_p: float,
    error_p: float,
    escalate_p: float,
    agent_version: str = "v1.0",
    base_time: datetime | None = None,
    time_step_seconds: int = 300,
) -> list[AgentDecision]:
    base = base_time or (datetime.utcnow() - timedelta(days=7))
    decisions = []
    for i in range(n):
        r = rng.random()
        if r < resolve_p:
            outcome = DecisionOutcome.RESOLVED
        elif r < resolve_p + error_p:
            outcome = DecisionOutcome.ERROR
        elif r < resolve_p + error_p + escalate_p:
            outcome = DecisionOutcome.ESCALATED
        else:
            outcome = DecisionOutcome.REJECTED
        ts = base + timedelta(seconds=i * time_step_seconds)
        decisions.append(
            _make_decision(
                case_id=f"{category.value}-{agent_version}-{i:04d}",
                category=category,
                outcome=outcome,
                confidence=max(0.01, min(0.99, rng.gauss(0.82, 0.07))),
                ts=ts,
                agent_version=agent_version,
            )
        )
    return decisions


@pytest.fixture
def config() -> GovernanceConfig:
    return GovernanceConfig.default()


@pytest.fixture
def store() -> DecisionStore:
    return DecisionStore()  # in-memory SQLite


@pytest.fixture
def populated_store(config: GovernanceConfig) -> DecisionStore:
    """Store pre-loaded with a healthy baseline for all high-risk categories.

    Data is placed 15 days ago so it falls within the default time-window
    baseline band [now-30d, now-7d).
    """
    store = DecisionStore()
    base_time = datetime.utcnow() - timedelta(days=15)
    for cat in [CaseCategory.BILLING_DISPUTE, CaseCategory.FRAUD_CLAIM, CaseCategory.POLICY_SENSITIVE, CaseCategory.ROUTINE]:
        decisions = make_decision_batch(cat, n=50, resolve_p=0.83, error_p=0.04, escalate_p=0.10,
                                        base_time=base_time)
        store.store_decisions_batch(decisions)
    return store


# ── Behavioral test rollback gate ──────────────────────────────────────────────
# Tracks failures for @pytest.mark.behavioral tests via a hook.
# If any behavioral test fails the session, a RollbackEvent is stored — this
# is the CI governance gate that blocks deployments when the agent regresses.

_behavioral_failures: list[str] = []
_behavioral_store: DecisionStore = DecisionStore()


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """
    Called after each test phase (setup/call/teardown).
    Track behavioral test failures so the rollback gate can fire after the session.
    """
    if report.when == "call" and report.failed:
        keywords = getattr(report, "keywords", {})
        if "behavioral" in keywords:
            _behavioral_failures.append(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """
    Called once after all tests complete.
    If any behavioral tests failed, store a RollbackEvent as the governance
    record of the regression.  In CI this record is inspectable via the API.
    """
    if _behavioral_failures:
        event = RollbackEvent(
            reason=(
                f"Behavioral regression suite failed ({len(_behavioral_failures)} test(s)): "
                + "; ".join(_behavioral_failures[:3])
                + (" ..." if len(_behavioral_failures) > 3 else "")
            ),
            triggered_by="behavioral_test_suite",
            drift_score=1.0,
        )
        try:
            _behavioral_store.store_rollback_event(event)
        except Exception:
            pass  # never let the governance hook crash the test runner
