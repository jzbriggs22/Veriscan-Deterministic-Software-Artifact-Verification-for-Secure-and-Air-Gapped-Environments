"""FastAPI application for the AI Governance MVP REST API."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from ..detection.detector import DriftDetector
from ..engine.alerts import AlertEngine
from ..engine.rollback import RollbackEngine
from ..engine.scheduler import DetectionScheduler
from ..governance.config import GovernanceConfig
from ..governance.schema import (
    AgentDecision,
    CaseCategory,
    DecisionOutcome,
)
from ..ingestion.ingestor import DecisionIngestor
from ..ingestion.store import DecisionStore
from .models import (
    AlertOut,
    CategoryHistoryOut,
    CategoryStatsOut,
    DecisionBatchIn,
    DecisionIn,
    DriftHistoryPointOut,
    DriftResultOut,
    GovernanceReportOut,
    GovernanceStatusOut,
    IngestionResult,
    MetricDriftOut,
    NormalMetricsOut,
    ResolveRollbackIn,
    ResolveRollbackOut,
    RollbackEventOut,
    SchedulerStatusOut,
)

app = FastAPI(
    title="AI Agent Governance API",
    description=(
        "Ingests agent decisions, detects per-category behavioral drift, "
        "and surfaces governance alerts before silent regressions cause damage."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Dependency injection ───────────────────────────────────────────────────────

# Singleton instances — in production, replace with proper DI / lifespan startup
_config: Optional[GovernanceConfig] = None
_store: Optional[DecisionStore] = None
_ingestor: Optional[DecisionIngestor] = None
_detector: Optional[DriftDetector] = None
_alert_engine: Optional[AlertEngine] = None
_rollback_engine: Optional[RollbackEngine] = None
_scheduler: Optional[DetectionScheduler] = None


def configure(
    config: GovernanceConfig,
    store: DecisionStore,
    scheduler: Optional[DetectionScheduler] = None,
) -> None:
    """Wire up application-level singletons. Call before serving requests."""
    global _config, _store, _ingestor, _detector, _alert_engine, _rollback_engine, _scheduler
    _config = config
    _store = store
    _ingestor = DecisionIngestor(store, config)
    _detector = DriftDetector(store, config)
    _alert_engine = AlertEngine(store, config)
    _rollback_engine = RollbackEngine(store, config)
    _scheduler = scheduler


def get_config() -> GovernanceConfig:
    if _config is None:
        raise HTTPException(status_code=503, detail="Service not configured")
    return _config


def get_store() -> DecisionStore:
    if _store is None:
        raise HTTPException(status_code=503, detail="Service not configured")
    return _store


def get_ingestor() -> DecisionIngestor:
    if _ingestor is None:
        raise HTTPException(status_code=503, detail="Service not configured")
    return _ingestor


def get_detector() -> DriftDetector:
    if _detector is None:
        raise HTTPException(status_code=503, detail="Service not configured")
    return _detector


def get_alert_engine() -> AlertEngine:
    if _alert_engine is None:
        raise HTTPException(status_code=503, detail="Service not configured")
    return _alert_engine


def get_rollback_engine() -> RollbackEngine:
    if _rollback_engine is None:
        raise HTTPException(status_code=503, detail="Service not configured")
    return _rollback_engine


def get_scheduler() -> Optional[DetectionScheduler]:
    return _scheduler  # may be None — endpoints must handle that gracefully


# ── Trend computation ──────────────────────────────────────────────────────────

def _compute_trend(history: list[dict]) -> tuple[str, float]:
    """
    Derive trend from the two most-recent drift history points.
    Returns (trend_label, delta) where delta = current - previous.
    Trend labels: improving | stable | degrading | unknown
    """
    valid = [p for p in history if not p["insufficient_data"]]
    if len(valid) < 2:
        return "unknown", 0.0
    current = valid[0]["drift_score"]
    previous = valid[1]["drift_score"]
    delta = current - previous
    if delta < -0.05:
        return "improving", delta
    if delta > 0.05:
        return "degrading", delta
    return "stable", delta


# ── Serialization helpers ──────────────────────────────────────────────────────

def _cat_stats_out(stats) -> Optional[CategoryStatsOut]:
    if stats is None:
        return None
    return CategoryStatsOut(
        category=stats.category.value,
        sample_size=stats.sample_size,
        resolution_rate=stats.resolution_rate,
        error_rate=stats.error_rate,
        escalation_rate=stats.escalation_rate,
        mean_confidence=stats.mean_confidence,
        p50_latency_ms=stats.p50_latency_ms,
    )


def _drift_result_out(r, trend: str = "unknown") -> DriftResultOut:
    return DriftResultOut(
        category=r.category.value,
        drift_score=r.drift_score,
        insufficient_data=r.insufficient_data,
        insufficient_data_reason=r.insufficient_data_reason,
        baseline_stats=_cat_stats_out(r.baseline_stats),
        recent_stats=_cat_stats_out(r.recent_stats),
        trend=trend,
        metric_drifts=[
            MetricDriftOut(
                metric_name=m.metric_name,
                baseline_value=m.baseline_value,
                recent_value=m.recent_value,
                absolute_change=m.absolute_change,
                relative_change_pct=m.relative_change_pct,
                effect_size=m.effect_size,
                p_value=m.p_value,
                drift_score=m.drift_score,
            )
            for m in r.metric_drifts
        ],
    )


def _history_point_out(p: dict) -> DriftHistoryPointOut:
    return DriftHistoryPointOut(
        result_id=p["result_id"],
        timestamp=p["timestamp"],
        category=p["category"],
        drift_score=p["drift_score"],
        insufficient_data=p["insufficient_data"],
        baseline_n=p["baseline_n"],
        recent_n=p["recent_n"],
        baseline_resolution_rate=p["baseline_resolution_rate"],
        recent_resolution_rate=p["recent_resolution_rate"],
        baseline_error_rate=p["baseline_error_rate"],
        recent_error_rate=p["recent_error_rate"],
    )


def _alert_out(a) -> AlertOut:
    return AlertOut(
        alert_id=a.alert_id,
        timestamp=a.timestamp,
        severity=a.severity.value,
        category=a.category.value,
        message=a.message,
        drift_score=a.drift_score,
        details=a.details,
        acknowledged_at=a.acknowledged_at,
        rollback_event_id=a.rollback_event_id,
    )


def _rollback_out(e) -> RollbackEventOut:
    return RollbackEventOut(
        event_id=e.event_id,
        timestamp=e.timestamp,
        reason=e.reason,
        triggered_by=e.triggered_by,
        category=e.category.value if e.category else None,
        drift_score=e.drift_score,
        agent_version=e.agent_version,
        is_active=e.is_active,
        resolved_at=e.resolved_at,
        resolution_note=e.resolution_note,
    )


def _decision_in_to_schema(d: DecisionIn) -> AgentDecision:
    try:
        cat = CaseCategory(d.category)
    except ValueError:
        cat = CaseCategory.UNKNOWN
    try:
        outcome = DecisionOutcome(d.outcome)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid outcome: {d.outcome!r}. Must be one of: resolved, error, escalated, rejected",
        )
    return AgentDecision(
        case_id=d.case_id,
        category=cat,
        outcome=outcome,
        confidence=d.confidence,
        timestamp=d.timestamp or datetime.utcnow(),
        agent_version=d.agent_version,
        processing_time_ms=d.processing_time_ms,
        case_text=d.case_text,
        metadata=d.metadata,
    )


# ── Ingestion endpoints ────────────────────────────────────────────────────────

@app.post("/decisions", response_model=IngestionResult, status_code=status.HTTP_201_CREATED,
          tags=["Ingestion"])
def ingest_decision(
    payload: DecisionIn,
    ingestor: DecisionIngestor = Depends(get_ingestor),
) -> IngestionResult:
    """Ingest a single agent decision. Auto-categorizes if category is 'unknown'."""
    decision = _decision_in_to_schema(payload)
    try:
        ingestor.ingest(decision)
        return IngestionResult(accepted=1, rejected=0, errors=[])
    except Exception as exc:
        return IngestionResult(accepted=0, rejected=1, errors=[str(exc)])


@app.post("/decisions/batch", response_model=IngestionResult, status_code=status.HTTP_201_CREATED,
          tags=["Ingestion"])
def ingest_batch(
    payload: DecisionBatchIn,
    ingestor: DecisionIngestor = Depends(get_ingestor),
) -> IngestionResult:
    """Ingest a batch of up to 1,000 agent decisions."""
    decisions = [_decision_in_to_schema(d) for d in payload.decisions]
    accepted, errors = ingestor.ingest_batch(decisions)
    return IngestionResult(accepted=accepted, rejected=len(errors), errors=errors)


# ── Governance query endpoints ─────────────────────────────────────────────────

@app.get("/governance/report", response_model=GovernanceReportOut, tags=["Governance"])
def get_governance_report(
    store: DecisionStore = Depends(get_store),
    detector: DriftDetector = Depends(get_detector),
    alert_engine: AlertEngine = Depends(get_alert_engine),
    rollback_engine: RollbackEngine = Depends(get_rollback_engine),
) -> GovernanceReportOut:
    """
    Run a full governance detection pass and return a complete report.
    Persists the results to drift_history so trend analysis is available.
    This is the primary endpoint for dashboard and monitoring integrations.
    """
    drift_results = detector.run_detection()
    alert_engine.process_drift_results(drift_results)
    store.store_drift_results_batch(drift_results)
    active_rollback = store.get_active_rollback()

    status_val = "healthy"
    for r in drift_results:
        if r.insufficient_data:
            continue
        if r.drift_score >= 0.70:
            status_val = "critical"
            break
        if r.drift_score >= 0.40:
            status_val = "drifting"

    # Enrich each result with trend from stored history
    enriched = []
    for r in drift_results:
        history = store.get_drift_history(r.category, limit=5)
        trend, _ = _compute_trend(history)
        enriched.append(_drift_result_out(r, trend=trend))

    return GovernanceReportOut(
        generated_at=datetime.utcnow(),
        status=status_val,
        drift_results=enriched,
        active_alerts=[_alert_out(a) for a in alert_engine.get_active_alerts()],
        active_rollback=_rollback_out(active_rollback) if active_rollback else None,
        total_decisions=store.total_count(),
        decisions_by_category=store.count_by_category(),
    )


@app.get("/governance/status", response_model=GovernanceStatusOut, tags=["Governance"])
def get_governance_status(
    store: DecisionStore = Depends(get_store),
    detector: DriftDetector = Depends(get_detector),
    alert_engine: AlertEngine = Depends(get_alert_engine),
    rollback_engine: RollbackEngine = Depends(get_rollback_engine),
) -> GovernanceStatusOut:
    """Lightweight status check — suitable for health probes."""
    active_alerts = alert_engine.get_active_alerts()
    rollback_active = rollback_engine.is_rollback_active()

    if rollback_active:
        status_val = "rollback_active"
    elif any(a.severity.value == "critical" for a in active_alerts):
        status_val = "critical"
    elif active_alerts:
        status_val = "drifting"
    else:
        status_val = "healthy"

    return GovernanceStatusOut(
        status=status_val,
        active_alert_count=len(active_alerts),
        rollback_active=rollback_active,
        total_decisions=store.total_count(),
    )


@app.get("/governance/alerts", response_model=list[AlertOut], tags=["Governance"])
def get_alerts(
    active_only: bool = True,
    limit: int = 50,
    store: DecisionStore = Depends(get_store),
) -> list[AlertOut]:
    """Return alerts. Set active_only=false to include acknowledged alerts."""
    if active_only:
        alerts = store.get_active_alerts()
    else:
        alerts = store.get_all_alerts(limit=limit)
    return [_alert_out(a) for a in alerts]


@app.post("/governance/alerts/{alert_id}/acknowledge", tags=["Governance"])
def acknowledge_alert(
    alert_id: str,
    store: DecisionStore = Depends(get_store),
) -> dict:
    """Acknowledge an alert by ID."""
    success = store.acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    return {"acknowledged": True, "alert_id": alert_id}


@app.post("/governance/rollback/resolve", response_model=ResolveRollbackOut, tags=["Governance"])
def resolve_rollback(
    payload: ResolveRollbackIn,
    store: DecisionStore = Depends(get_store),
    rollback_engine: RollbackEngine = Depends(get_rollback_engine),
) -> ResolveRollbackOut:
    """Mark the active rollback as resolved."""
    active = store.get_active_rollback()
    if active is None:
        return ResolveRollbackOut(resolved=False, message="No active rollback to resolve")
    rollback_engine.resolve_rollback(payload.note)
    return ResolveRollbackOut(resolved=True, message=f"Rollback {active.event_id} resolved")


# ── Metrics endpoint ───────────────────────────────────────────────────────────

@app.get("/metrics", response_model=NormalMetricsOut, tags=["Metrics"])
def get_normal_metrics(
    store: DecisionStore = Depends(get_store),
) -> NormalMetricsOut:
    """
    Standard ops metrics — the view that looks fine while the agent silently drifts.
    Compare with /governance/report to see what governance catches that ops misses.
    """
    decisions = store.get_all_recent(limit=500)
    total = len(decisions)
    if total == 0:
        return NormalMetricsOut(
            total_decisions=0,
            overall_resolution_rate=0.0,
            overall_error_rate=0.0,
            mean_processing_time_ms=0.0,
            decisions_by_category={},
        )
    resolved = sum(1 for d in decisions if d.outcome.value == "resolved")
    errors = sum(1 for d in decisions if d.outcome.value == "error")
    mean_pt = sum(d.processing_time_ms for d in decisions) / total
    return NormalMetricsOut(
        total_decisions=store.total_count(),
        overall_resolution_rate=resolved / total,
        overall_error_rate=errors / total,
        mean_processing_time_ms=mean_pt,
        decisions_by_category=store.count_by_category(),
    )


# ── Drift history endpoints ────────────────────────────────────────────────────

@app.get(
    "/governance/categories/{category}/history",
    response_model=CategoryHistoryOut,
    tags=["Governance"],
)
def get_category_history(
    category: str,
    limit: int = Query(default=50, ge=1, le=500),
    hours: Optional[int] = Query(default=None, ge=1, description="Restrict to last N hours"),
    store: DecisionStore = Depends(get_store),
) -> CategoryHistoryOut:
    """
    Return the drift score history for a single category.
    Use this to see if the agent is improving, stable, or degrading over time.
    """
    try:
        cat = CaseCategory(category)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Unknown category: {category!r}")

    since = datetime.utcnow() - timedelta(hours=hours) if hours else None
    history = store.get_drift_history(cat, limit=limit, since=since)
    trend, delta = _compute_trend(history)
    current_score = history[0]["drift_score"] if history else 0.0

    return CategoryHistoryOut(
        category=category,
        points=[_history_point_out(p) for p in history],
        current_drift_score=current_score,
        trend=trend,
        trend_delta=delta,
        total_detection_cycles=len(history),
    )


@app.get(
    "/governance/history",
    response_model=list[DriftHistoryPointOut],
    tags=["Governance"],
)
def get_all_drift_history(
    limit: int = Query(default=100, ge=1, le=1000),
    hours: Optional[int] = Query(default=None, ge=1, description="Restrict to last N hours"),
    store: DecisionStore = Depends(get_store),
) -> list[DriftHistoryPointOut]:
    """Return drift history across all categories, newest first."""
    since = datetime.utcnow() - timedelta(hours=hours) if hours else None
    history = store.get_all_drift_history(limit=limit, since=since)
    return [_history_point_out(p) for p in history]


# ── Scheduler endpoints ────────────────────────────────────────────────────────

@app.get("/scheduler/status", response_model=SchedulerStatusOut, tags=["System"])
def get_scheduler_status(
    scheduler: Optional[DetectionScheduler] = Depends(get_scheduler),
) -> SchedulerStatusOut:
    """Return background detection scheduler state."""
    if scheduler is None:
        return SchedulerStatusOut(
            running=False,
            interval_seconds=0.0,
            cycle_count=0,
            last_run_at=None,
            last_error=None,
        )
    return SchedulerStatusOut(
        running=scheduler.is_running(),
        interval_seconds=scheduler._interval_seconds,
        cycle_count=scheduler.cycle_count,
        last_run_at=scheduler.last_run_at,
        last_error=scheduler.last_error,
    )


@app.post("/scheduler/run-now", tags=["System"])
def trigger_detection_now(
    store: DecisionStore = Depends(get_store),
    detector: DriftDetector = Depends(get_detector),
    alert_engine: AlertEngine = Depends(get_alert_engine),
    rollback_engine: RollbackEngine = Depends(get_rollback_engine),
) -> dict:
    """
    Trigger an immediate detection cycle outside the normal schedule.
    Useful for on-demand checks from CI/CD pipelines or manual inspection.
    """
    drift_results = detector.run_detection()
    new_alerts = alert_engine.process_drift_results(drift_results)
    rollback = rollback_engine.maybe_trigger(drift_results)
    store.store_drift_results_batch(drift_results)

    return {
        "categories_checked": len(drift_results),
        "new_alerts": len(new_alerts),
        "rollback_triggered": rollback is not None,
        "rollback_event_id": rollback.event_id if rollback else None,
        "drift_scores": {
            r.category.value: round(r.drift_score, 4)
            for r in drift_results
            if not r.insufficient_data
        },
    }


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health() -> dict:
    return {"status": "ok", "version": app.version}
