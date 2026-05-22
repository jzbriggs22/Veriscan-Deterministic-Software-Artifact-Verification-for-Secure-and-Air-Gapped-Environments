"""Pydantic request/response models for the governance REST API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ── Inbound ────────────────────────────────────────────────────────────────────

class DecisionIn(BaseModel):
    """A single agent decision submitted for ingestion."""
    case_id: str = Field(..., min_length=1, description="Unique case identifier")
    category: str = Field("unknown", description="CaseCategory value; 'unknown' triggers auto-categorization")
    outcome: str = Field(..., description="resolved | error | escalated | rejected")
    confidence: float = Field(..., ge=0.0, le=1.0)
    timestamp: Optional[datetime] = Field(None, description="ISO-8601; defaults to server time if omitted")
    agent_version: str = Field(..., min_length=1)
    processing_time_ms: float = Field(..., ge=0.0)
    case_text: str = Field("", description="Free-text case description for auto-categorization")
    metadata: dict[str, Any] = Field(default_factory=dict)


class DecisionBatchIn(BaseModel):
    decisions: list[DecisionIn] = Field(..., min_length=1, max_length=1000)


# ── Outbound ───────────────────────────────────────────────────────────────────

class IngestionResult(BaseModel):
    accepted: int
    rejected: int
    errors: list[str]


class MetricDriftOut(BaseModel):
    metric_name: str
    baseline_value: float
    recent_value: float
    absolute_change: float
    relative_change_pct: float
    effect_size: float
    p_value: float
    drift_score: float


class CategoryStatsOut(BaseModel):
    category: str
    sample_size: int
    resolution_rate: float
    error_rate: float
    escalation_rate: float
    mean_confidence: float
    p50_latency_ms: float


class DriftResultOut(BaseModel):
    category: str
    drift_score: float
    insufficient_data: bool
    insufficient_data_reason: str
    baseline_stats: Optional[CategoryStatsOut]
    recent_stats: Optional[CategoryStatsOut]
    metric_drifts: list[MetricDriftOut]
    trend: str = "unknown"  # improving | stable | degrading | unknown


class DriftHistoryPointOut(BaseModel):
    result_id: str
    timestamp: datetime
    category: str
    drift_score: float
    insufficient_data: bool
    baseline_n: int
    recent_n: int
    baseline_resolution_rate: float
    recent_resolution_rate: float
    baseline_error_rate: float
    recent_error_rate: float


class CategoryHistoryOut(BaseModel):
    category: str
    points: list[DriftHistoryPointOut]
    current_drift_score: float
    trend: str                    # improving | stable | degrading | unknown
    trend_delta: float            # drift_score change vs prior point
    total_detection_cycles: int


class SchedulerStatusOut(BaseModel):
    running: bool
    interval_seconds: float
    cycle_count: int
    last_run_at: Optional[datetime]
    last_error: Optional[str]


class AlertOut(BaseModel):
    alert_id: str
    timestamp: datetime
    severity: str
    category: str
    message: str
    drift_score: float
    details: dict[str, Any]
    acknowledged_at: Optional[datetime]
    rollback_event_id: Optional[str]


class RollbackEventOut(BaseModel):
    event_id: str
    timestamp: datetime
    reason: str
    triggered_by: str
    category: Optional[str]
    drift_score: float
    agent_version: str
    is_active: bool
    resolved_at: Optional[datetime]
    resolution_note: str


class GovernanceReportOut(BaseModel):
    generated_at: datetime
    status: str
    drift_results: list[DriftResultOut]
    active_alerts: list[AlertOut]
    active_rollback: Optional[RollbackEventOut]
    total_decisions: int
    decisions_by_category: dict[str, int]


class GovernanceStatusOut(BaseModel):
    status: str
    active_alert_count: int
    rollback_active: bool
    total_decisions: int


class ResolveRollbackIn(BaseModel):
    note: str = Field(..., min_length=1)


class ResolveRollbackOut(BaseModel):
    resolved: bool
    message: str


class NormalMetricsOut(BaseModel):
    total_decisions: int
    overall_resolution_rate: float
    overall_error_rate: float
    mean_processing_time_ms: float
    decisions_by_category: dict[str, int]


class DecisionOut(BaseModel):
    """A single agent decision — returned by the category drill-down endpoint."""
    decision_id: str
    case_id: str
    category: str
    outcome: str
    confidence: float
    timestamp: datetime
    agent_version: str
    processing_time_ms: float
    case_text: str
    metadata: dict[str, Any]


class CategoryDecisionsOut(BaseModel):
    """Drill-down: recent decisions for one category, with aggregate stats."""
    category: str
    hours: int
    total: int
    decisions: list[DecisionOut]
    outcome_counts: dict[str, int]
    resolution_rate: float
    error_rate: float
    escalation_rate: float
    mean_confidence: float


class EventBrokerStatusOut(BaseModel):
    subscriber_count: int
    published_total: int


# ── Pre-flight validation ──────────────────────────────────────────────────────

class PreflightDecisionIn(BaseModel):
    """A candidate agent decision submitted for pre-deployment validation."""
    case_category: str
    risk_level: str
    decision: str = Field(..., min_length=1)
    confidence: float = Field(..., ge=0.0, le=1.0)
    flags: list[str] = Field(default_factory=list)
    _expected_category: str = ""  # optional ground-truth annotation


class PreflightBatchIn(BaseModel):
    agent_version: str = Field(..., min_length=1)
    decisions: list[dict[str, Any]] = Field(..., min_length=1, max_length=500)


class CategoryPreflightResultOut(BaseModel):
    category: str
    total: int
    valid_schema: int
    resolution_rate: float
    error_rate: float
    escalation_rate: float
    mean_confidence: float
    passed: bool
    threshold_violations: list[str]


class PreflightReportOut(BaseModel):
    passed: bool
    agent_version: str
    generated_at: datetime
    total_submitted: int
    valid_decisions: int
    schema_error_count: int
    recommendation: str   # SAFE_TO_DEPLOY | WARNING | BLOCKED
    summary: str
    threshold_violations: list[str]
    high_risk_failures: list[str]
    category_results: list[CategoryPreflightResultOut]


# ── Agent version tracking ─────────────────────────────────────────────────────

class AgentVersionSummaryOut(BaseModel):
    agent_version: str
    total: int
    resolution_rate: float
    error_rate: float
    escalation_rate: float
    mean_confidence: float
    first_seen: Optional[str]
    last_seen: Optional[str]
    decisions_by_category: dict[str, int]


class VersionComparisonOut(BaseModel):
    version_a: str
    version_b: str
    total_a: int
    total_b: int
    resolution_rate_delta: float   # b - a; positive = improved
    error_rate_delta: float        # b - a; negative = improved
    escalation_rate_delta: float
    confidence_delta: float
    verdict: str                   # IMPROVED | DEGRADED | STABLE | INSUFFICIENT_DATA
    notes: list[str]
