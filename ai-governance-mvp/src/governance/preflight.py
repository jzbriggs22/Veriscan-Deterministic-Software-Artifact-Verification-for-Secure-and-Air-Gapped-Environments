"""
Pre-deployment governance validation gate.

PreflightValidator checks a batch of agent decisions (from a candidate
agent version) against governance thresholds before the version goes live.
This implements the "criteria defined before the agent runs" requirement
as a deployable check: fail here, not in production.

Usage:
  validator = PreflightValidator(config)
  report = validator.validate_batch(decisions, agent_version="v2.0.1")
  if not report.passed:
      raise DeploymentBlocked(report.recommendation)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from ..governance.config import GovernanceConfig
from ..governance.schema import CaseCategory, DecisionOutcome
from ..governance.structured import GovernanceDecision, StructuredOutputError, get_parser


# ── Result types ───────────────────────────────────────────────────────────────

@dataclass
class CategoryPreflightResult:
    category: str
    total: int
    valid_schema: int           # passed GovernanceDecision validation
    high_risk_correct: int      # has expected high-risk level when category demands it
    resolution_rate: float
    error_rate: float
    escalation_rate: float
    rejection_rate: float
    mean_confidence: float
    schema_errors: list[str] = field(default_factory=list)
    threshold_violations: list[str] = field(default_factory=list)
    passed: bool = True


@dataclass
class PreflightReport:
    """
    Full pre-deployment validation report.

    ``recommendation`` is one of:
      SAFE_TO_DEPLOY  — all checks passed
      WARNING         — soft threshold breached; human review recommended
      BLOCKED         — hard threshold breached; deployment should be blocked
    """
    passed: bool
    agent_version: str
    generated_at: datetime
    total_submitted: int
    valid_decisions: int
    schema_error_count: int
    category_results: list[CategoryPreflightResult]
    threshold_violations: list[str]
    high_risk_failures: list[str]
    recommendation: str  # SAFE_TO_DEPLOY | WARNING | BLOCKED
    summary: str

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "agent_version": self.agent_version,
            "generated_at": self.generated_at.isoformat(),
            "total_submitted": self.total_submitted,
            "valid_decisions": self.valid_decisions,
            "schema_error_count": self.schema_error_count,
            "recommendation": self.recommendation,
            "summary": self.summary,
            "threshold_violations": self.threshold_violations,
            "high_risk_failures": self.high_risk_failures,
            "category_results": [
                {
                    "category": r.category,
                    "total": r.total,
                    "valid_schema": r.valid_schema,
                    "resolution_rate": r.resolution_rate,
                    "error_rate": r.error_rate,
                    "escalation_rate": r.escalation_rate,
                    "mean_confidence": r.mean_confidence,
                    "passed": r.passed,
                    "threshold_violations": r.threshold_violations,
                }
                for r in self.category_results
            ],
        }


# ── Outcome heuristic (mirrors ingestor) ───────────────────────────────────────

def _infer_outcome(decision_text: str) -> DecisionOutcome:
    dl = decision_text.lower()
    if any(w in dl for w in ("escalat", "human review", "manual")):
        return DecisionOutcome.ESCALATED
    if any(w in dl for w in ("error", "fail", "unable", "cannot")):
        return DecisionOutcome.ERROR
    if any(w in dl for w in ("reject", "deny", "block", "decline")):
        return DecisionOutcome.REJECTED
    return DecisionOutcome.RESOLVED


# ── Validator ──────────────────────────────────────────────────────────────────

_HIGH_RISK_CATEGORIES = {
    CaseCategory.BILLING_DISPUTE,
    CaseCategory.FRAUD_CLAIM,
    CaseCategory.POLICY_SENSITIVE,
}

_HIGH_RISK_LEVELS = {"high", "critical"}


class PreflightValidator:
    """
    Validates a batch of agent decisions against governance thresholds.

    Accepts raw dicts (as produced by agent JSON output) or already-parsed
    GovernanceDecision objects.  Parses, categorises, and checks each
    decision; aggregates per-category stats; evaluates against thresholds.
    """

    def __init__(self, config: GovernanceConfig) -> None:
        self._config = config
        self._parser = get_parser()

    def validate_batch(
        self,
        decisions: list[dict],
        agent_version: str = "unknown",
    ) -> PreflightReport:
        """
        Validate a list of raw decision dicts.

        Each dict must be parseable as GovernanceDecision.  Optionally include
        ``_expected_category`` (str) to check that the agent's category field
        matches the expected value.

        Returns a PreflightReport with pass/fail verdict and per-category details.
        """
        parsed: list[tuple[GovernanceDecision, dict]] = []
        schema_errors: list[str] = []

        for i, raw in enumerate(decisions):
            schema_only = {k: v for k, v in raw.items() if not k.startswith("_")}
            try:
                gd = self._parser.validate(schema_only)
                parsed.append((gd, raw))
            except StructuredOutputError as exc:
                schema_errors.append(f"decision[{i}]: {exc}")

        # Group by category
        by_category: dict[str, list[tuple[GovernanceDecision, dict]]] = {}
        for gd, raw in parsed:
            by_category.setdefault(gd.case_category, []).append((gd, raw))

        category_results: list[CategoryPreflightResult] = []
        all_violations: list[str] = []
        high_risk_failures: list[str] = []

        for cat_str, entries in by_category.items():
            result = self._check_category(cat_str, entries)
            category_results.append(result)
            all_violations.extend(result.threshold_violations)

        # Check high-risk level correctness across all parsed decisions
        for gd, raw in parsed:
            try:
                cat = CaseCategory(gd.case_category)
            except ValueError:
                continue
            if cat in _HIGH_RISK_CATEGORIES and gd.risk_level not in _HIGH_RISK_LEVELS:
                msg = (
                    f"{cat.value}: risk_level={gd.risk_level!r} "
                    f"(expected high or critical for this category)"
                )
                high_risk_failures.append(msg)

        # Check expected_category annotations if provided
        for i, (gd, raw) in enumerate([(g, r) for g, r in parsed]):
            expected = raw.get("_expected_category")
            if expected and expected != gd.case_category:
                high_risk_failures.append(
                    f"decision[{i}]: case_category={gd.case_category!r} "
                    f"but expected {expected!r}"
                )

        passed = (
            len(schema_errors) == 0
            and len(all_violations) == 0
            and len(high_risk_failures) == 0
        )

        # Determine recommendation
        if not passed:
            hard_fail = all_violations or high_risk_failures
            recommendation = "BLOCKED" if hard_fail else "WARNING"
        else:
            # Check soft warnings: schema errors but recoverable
            recommendation = "SAFE_TO_DEPLOY"

        # Summary string
        if recommendation == "SAFE_TO_DEPLOY":
            summary = (
                f"All {len(parsed)} decisions valid. "
                f"{len(by_category)} categories checked. Ready for deployment."
            )
        elif recommendation == "WARNING":
            summary = (
                f"{len(schema_errors)} schema errors in {len(decisions)} decisions. "
                f"Human review recommended before deployment."
            )
        else:
            issues = len(all_violations) + len(high_risk_failures) + len(schema_errors)
            summary = (
                f"{issues} governance issue(s) found. "
                f"Deployment blocked: {'; '.join((all_violations + high_risk_failures)[:2])}"
            )

        return PreflightReport(
            passed=passed,
            agent_version=agent_version,
            generated_at=datetime.utcnow(),
            total_submitted=len(decisions),
            valid_decisions=len(parsed),
            schema_error_count=len(schema_errors),
            category_results=category_results,
            threshold_violations=all_violations,
            high_risk_failures=high_risk_failures,
            recommendation=recommendation,
            summary=summary,
        )

    def validate_governance_decisions(
        self,
        decisions: list[GovernanceDecision],
        agent_version: str = "unknown",
    ) -> PreflightReport:
        """Convenience: validate already-parsed GovernanceDecision objects."""
        return self.validate_batch(
            [gd.to_dict() for gd in decisions],
            agent_version=agent_version,
        )

    # ── Internal ───────────────────────────────────────────────────────────────

    def _check_category(
        self,
        cat_str: str,
        entries: list[tuple[GovernanceDecision, dict]],
    ) -> CategoryPreflightResult:
        n = len(entries)
        thresholds = self._config.thresholds_for(
            CaseCategory(cat_str) if cat_str in CaseCategory._value2member_map_ else CaseCategory.UNKNOWN
        )

        resolved = error = escalated = rejected = 0
        total_confidence = 0.0
        high_risk_correct = 0

        for gd, _ in entries:
            outcome = _infer_outcome(gd.decision)
            if outcome == DecisionOutcome.RESOLVED:
                resolved += 1
            elif outcome == DecisionOutcome.ERROR:
                error += 1
            elif outcome == DecisionOutcome.ESCALATED:
                escalated += 1
            else:
                rejected += 1
            total_confidence += gd.confidence
            if gd.risk_level in _HIGH_RISK_LEVELS:
                high_risk_correct += 1

        resolution_rate = resolved / n
        error_rate = error / n
        escalation_rate = escalated / n
        rejection_rate = rejected / n
        mean_confidence = total_confidence / n

        violations: list[str] = []

        # Error rate threshold
        if error_rate > thresholds.max_error_rate:
            violations.append(
                f"{cat_str}: error_rate {error_rate:.1%} exceeds threshold {thresholds.max_error_rate:.1%}"
            )

        # Minimum sample size
        if n < thresholds.min_detection_size:
            violations.append(
                f"{cat_str}: only {n} decisions, minimum is {thresholds.min_detection_size}"
            )

        return CategoryPreflightResult(
            category=cat_str,
            total=n,
            valid_schema=n,  # all entries here were already parsed successfully
            high_risk_correct=high_risk_correct,
            resolution_rate=resolution_rate,
            error_rate=error_rate,
            escalation_rate=escalation_rate,
            rejection_rate=rejection_rate,
            mean_confidence=mean_confidence,
            threshold_violations=violations,
            passed=len(violations) == 0,
        )
