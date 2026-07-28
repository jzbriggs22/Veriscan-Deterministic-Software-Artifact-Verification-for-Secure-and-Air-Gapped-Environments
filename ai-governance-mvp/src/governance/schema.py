"""Core data models for AI agent governance."""
from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class CaseCategory(str, Enum):
    BILLING_DISPUTE = "billing_dispute"
    FRAUD_CLAIM = "fraud_claim"
    POLICY_SENSITIVE = "policy_sensitive"
    ROUTINE = "routine"
    UNKNOWN = "unknown"

    def is_high_risk(self) -> bool:
        return self in (
            CaseCategory.BILLING_DISPUTE,
            CaseCategory.FRAUD_CLAIM,
            CaseCategory.POLICY_SENSITIVE,
        )


class DecisionOutcome(str, Enum):
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    REJECTED = "rejected"
    ERROR = "error"


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class GovernanceStatus(str, Enum):
    HEALTHY = "healthy"
    DRIFTING = "drifting"
    CRITICAL = "critical"
    ROLLBACK_TRIGGERED = "rollback_triggered"


@dataclass
class AgentDecision:
    """Single decision made by the agent on a support case."""
    case_id: str
    category: CaseCategory
    outcome: DecisionOutcome
    confidence: float  # 0.0–1.0
    timestamp: datetime
    agent_version: str
    processing_time_ms: float
    case_text: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")
        if self.processing_time_ms < 0:
            raise ValueError("processing_time_ms must be non-negative")
        # The store and detection windows operate on naive UTC datetimes;
        # normalize timezone-aware timestamps (e.g. ISO-8601 with 'Z' or an
        # offset, as parsed at the API boundary) instead of failing later on
        # naive-vs-aware comparisons.
        if self.timestamp.tzinfo is not None:
            self.timestamp = self.timestamp.astimezone(timezone.utc).replace(tzinfo=None)


@dataclass
class CategoryStats:
    """Aggregate statistics for a cohort of decisions in one category."""
    category: CaseCategory
    sample_size: int
    resolution_rate: float  # proportion with outcome RESOLVED
    escalation_rate: float
    error_rate: float
    mean_confidence: float
    p50_latency_ms: float

    # Raw counts for statistical tests
    resolved_count: int = 0
    error_count: int = 0
    escalation_count: int = 0

    @classmethod
    def from_decisions(cls, category: CaseCategory, decisions: list[AgentDecision]) -> "CategoryStats":
        n = len(decisions)
        if n == 0:
            return cls(
                category=category, sample_size=0,
                resolution_rate=0.0, escalation_rate=0.0,
                error_rate=0.0, mean_confidence=0.0, p50_latency_ms=0.0,
            )
        resolved = sum(1 for d in decisions if d.outcome == DecisionOutcome.RESOLVED)
        escalated = sum(1 for d in decisions if d.outcome == DecisionOutcome.ESCALATED)
        errors = sum(1 for d in decisions if d.outcome == DecisionOutcome.ERROR)
        latencies = sorted(d.processing_time_ms for d in decisions)
        p50 = latencies[n // 2]
        return cls(
            category=category,
            sample_size=n,
            resolution_rate=resolved / n,
            escalation_rate=escalated / n,
            error_rate=errors / n,
            mean_confidence=sum(d.confidence for d in decisions) / n,
            p50_latency_ms=p50,
            resolved_count=resolved,
            error_count=errors,
            escalation_count=escalated,
        )


@dataclass
class MetricDrift:
    """Drift measurement for a single metric between baseline and recent window."""
    metric_name: str
    baseline_value: float
    recent_value: float
    absolute_change: float
    relative_change_pct: float  # positive = increase
    effect_size: float          # Cohen's h for proportions
    p_value: float              # two-proportion z-test
    drift_score: float          # 0.0–1.0

    @property
    def is_significant(self) -> bool:
        return self.p_value < 0.05 and abs(self.effect_size) > 0.2


@dataclass
class DriftResult:
    """Drift detection result for one category in one detection cycle."""
    result_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    category: CaseCategory = CaseCategory.UNKNOWN
    drift_score: float = 0.0          # 0.0 = no drift, 1.0 = maximum drift
    baseline_stats: Optional[CategoryStats] = None
    recent_stats: Optional[CategoryStats] = None
    metric_drifts: list[MetricDrift] = field(default_factory=list)
    insufficient_data: bool = False
    insufficient_data_reason: str = ""

    @property
    def is_high_risk(self) -> bool:
        return self.category.is_high_risk()

    def worst_metric(self) -> Optional[MetricDrift]:
        if not self.metric_drifts:
            return None
        return max(self.metric_drifts, key=lambda m: m.drift_score)


@dataclass
class DriftAlert:
    """Alert generated when drift exceeds a threshold."""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    severity: AlertSeverity = AlertSeverity.INFO
    category: CaseCategory = CaseCategory.UNKNOWN
    message: str = ""
    drift_score: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    acknowledged_at: Optional[datetime] = None
    rollback_event_id: Optional[str] = None

    @property
    def is_active(self) -> bool:
        return self.acknowledged_at is None


@dataclass
class RollbackEvent:
    """Record of a rollback being triggered."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    reason: str = ""
    triggered_by: str = "governance_engine"
    category: Optional[CaseCategory] = None
    drift_score: float = 0.0
    agent_version: str = ""
    resolved_at: Optional[datetime] = None
    resolution_note: str = ""

    @property
    def is_active(self) -> bool:
        return self.resolved_at is None


@dataclass
class NormalMetrics:
    """Standard operational metrics that mask governance issues."""
    window_size: int
    overall_resolution_rate: float
    overall_error_rate: float
    overall_escalation_rate: float
    mean_response_time_ms: float
    p95_response_time_ms: float
    total_volume: int
    high_risk_volume: int
    uptime_pct: float = 99.9


