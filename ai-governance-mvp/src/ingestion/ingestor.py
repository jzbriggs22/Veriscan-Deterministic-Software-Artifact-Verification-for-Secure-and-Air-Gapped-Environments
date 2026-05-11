"""Decision ingestor: validates, categorizes, and stores agent decisions."""
from __future__ import annotations

import re
from datetime import datetime

from ..governance.config import GovernanceConfig
from ..governance.schema import AgentDecision, CaseCategory
from .store import DecisionStore


class ValidationError(Exception):
    pass


class DecisionIngestor:
    """Validates decisions and routes them into the store with correct categorization."""

    def __init__(self, store: DecisionStore, config: GovernanceConfig) -> None:
        self._store = store
        self._config = config
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
        if decision.timestamp > datetime.utcnow().replace(microsecond=0).replace(microsecond=999999):
            return False, "timestamp is in the future"
        return True, ""

    def categorize(self, decision: AgentDecision) -> CaseCategory:
        """
        Return the best-matching CaseCategory based on case_text patterns.
        Falls back to the decision's own category if already set to a non-UNKNOWN value,
        or UNKNOWN if no pattern matches.
        """
        if decision.category != CaseCategory.UNKNOWN and decision.category != CaseCategory.ROUTINE:
            # Trust explicit category set by the caller
            return decision.category

        text = decision.case_text
        for cat, patterns in self._compiled.items():
            if any(p.search(text) for p in patterns):
                return cat

        # If the caller set ROUTINE explicitly, respect it; else UNKNOWN
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

        # Apply text-based categorization when caller sends UNKNOWN
        if decision.category in (CaseCategory.UNKNOWN,):
            decision.category = self.categorize(decision)

        self._store.store_decision(decision)
        return decision

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
