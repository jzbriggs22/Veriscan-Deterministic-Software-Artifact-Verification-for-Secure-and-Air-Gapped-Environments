"""Decision ingestor: validates, categorizes, and stores agent decisions."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from ..governance.config import GovernanceConfig
from ..governance.schema import AgentDecision, CaseCategory, DecisionOutcome
from ..governance.structured import (
    GovernanceDecision,
    StructuredOutputError,
    StructuredOutputParser,
    get_parser,
)
from .store import DecisionStore


class ValidationError(Exception):
    pass


# ── Risk-level → CaseCategory mapping ─────────────────────────────────────────

_RISK_TO_CATEGORY: dict[str, CaseCategory] = {
    # Explicit high-risk levels trigger high-risk categories when no better
    # category match is available from the case_category field.
    "critical": CaseCategory.FRAUD_CLAIM,  # critical risk defaults to fraud
    "high": CaseCategory.BILLING_DISPUTE,
}


def _governance_decision_to_agent_decision(
    gd: GovernanceDecision,
    case_id: str,
    agent_version: str,
    processing_time_ms: float = 500.0,
    timestamp: Optional[datetime] = None,
) -> AgentDecision:
    """
    Convert a GovernanceDecision (structured output contract) to an AgentDecision
    (storage / detection schema).

    Case category resolution order:
      1. GovernanceDecision.case_category mapped to CaseCategory enum
      2. If mapping fails, derive from risk_level
      3. Fall back to UNKNOWN
    """
    # Resolve category
    try:
        category = CaseCategory(gd.case_category)
    except ValueError:
        category = _RISK_TO_CATEGORY.get(gd.risk_level, CaseCategory.UNKNOWN)

    # Resolve outcome from decision text heuristics (conservative)
    dl = gd.decision.lower()
    if any(w in dl for w in ("escalat", "human review", "manual")):
        outcome = DecisionOutcome.ESCALATED
    elif any(w in dl for w in ("error", "fail", "unable", "cannot")):
        outcome = DecisionOutcome.ERROR
    elif any(w in dl for w in ("reject", "deny", "block", "decline")):
        outcome = DecisionOutcome.REJECTED
    else:
        outcome = DecisionOutcome.RESOLVED

    return AgentDecision(
        case_id=case_id,
        category=category,
        outcome=outcome,
        confidence=gd.confidence,
        timestamp=timestamp or datetime.utcnow(),
        agent_version=agent_version,
        processing_time_ms=processing_time_ms,
        metadata={
            "risk_level": gd.risk_level,
            "flags": gd.flags,
            "governance_decision": gd.decision,
        },
    )


class DecisionIngestor:
    """Validates decisions and routes them into the store with correct categorization."""

    def __init__(self, store: DecisionStore, config: GovernanceConfig) -> None:
        self._store = store
        self._config = config
        self._parser: StructuredOutputParser = get_parser()
        # Pre-compile category patterns
        self._compiled: dict[CaseCategory, list[re.Pattern]] = {}
        for cat_str, patterns in config.category_patterns.items():
            try:
                cat = CaseCategory(cat_str)
            except ValueError:
                continue
            self._compiled[cat] = [re.compile(p) for p in patterns]

    def validate(self, decision: AgentDecision) -> tuple[bool, str]:
        """Return (ok, error_message). Empty error_message means valid."""
        if not decision.case_id:
            return False, "case_id is required"
        if not decision.agent_version:
            return False, "agent_version is required"
        if not (0.0 <= decision.confidence <= 1.0):
            return False, f"confidence must be in [0, 1], got {decision.confidence}"
        if decision.processing_time_ms < 0:
            return False, "processing_time_ms must be non-negative"
        # Grace up to the end of the current second to absorb clock skew.
        if decision.timestamp > datetime.utcnow().replace(microsecond=999999):
            return False, "timestamp is in the future"
        return True, ""

    def categorize(self, decision: AgentDecision) -> CaseCategory:
        """
        Return the best-matching CaseCategory based on case_text patterns.
        Falls back to the decision's own category if already set to a non-UNKNOWN value,
        or UNKNOWN if no pattern matches.
        """
        if decision.category != CaseCategory.UNKNOWN and decision.category != CaseCategory.ROUTINE:
            return decision.category

        text = decision.case_text
        for cat, patterns in self._compiled.items():
            if any(p.search(text) for p in patterns):
                return cat

        if decision.category == CaseCategory.ROUTINE:
            return CaseCategory.ROUTINE
        return CaseCategory.UNKNOWN

    def ingest(self, decision: AgentDecision) -> AgentDecision:
        """
        Validate, categorize (if needed), and store the decision.
        Returns the (possibly mutated) decision with category applied.
        Raises ValidationError on bad input.
        """
        ok, msg = self.validate(decision)
        if not ok:
            raise ValidationError(f"Invalid decision {decision.decision_id}: {msg}")

        if decision.category in (CaseCategory.UNKNOWN,):
            decision.category = self.categorize(decision)

        self._store.store_decision(decision)
        return decision

    def ingest_governance_decision(
        self,
        gd: GovernanceDecision,
        case_id: str,
        agent_version: str,
        processing_time_ms: float = 500.0,
        timestamp: Optional[datetime] = None,
    ) -> AgentDecision:
        """
        Ingest a GovernanceDecision (structured output) directly.

        Converts to AgentDecision, runs normal validation + categorization,
        and stores. This is the preferred path when the agent produces
        structured output via outlines or instructor.
        """
        agent_decision = _governance_decision_to_agent_decision(
            gd, case_id, agent_version, processing_time_ms, timestamp
        )
        return self.ingest(agent_decision)

    def parse_and_ingest(
        self,
        raw_output: str,
        case_id: str,
        agent_version: str,
        processing_time_ms: float = 500.0,
        timestamp: Optional[datetime] = None,
    ) -> AgentDecision:
        """
        Parse raw agent text output as a GovernanceDecision, then ingest it.

        Raises StructuredOutputError if the text cannot be parsed.
        Raises ValidationError if the parsed decision is invalid.
        """
        gd = self._parser.parse(raw_output)
        return self.ingest_governance_decision(
            gd, case_id, agent_version, processing_time_ms, timestamp
        )

    def ingest_batch(
        self, decisions: list[AgentDecision]
    ) -> tuple[int, list[str]]:
        """
        Ingest a batch.  Returns (accepted_count, list_of_error_messages).
        Invalid decisions are skipped but do not abort the batch.
        """
        accepted: list[AgentDecision] = []
        errors: list[str] = []

        for d in decisions:
            ok, msg = self.validate(d)
            if not ok:
                errors.append(f"{d.decision_id}: {msg}")
                continue
            if d.category == CaseCategory.UNKNOWN:
                d.category = self.categorize(d)
            accepted.append(d)

        if accepted:
            self._store.store_decisions_batch(accepted)

        return len(accepted), errors

