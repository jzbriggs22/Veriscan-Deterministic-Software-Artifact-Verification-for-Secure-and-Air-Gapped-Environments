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
