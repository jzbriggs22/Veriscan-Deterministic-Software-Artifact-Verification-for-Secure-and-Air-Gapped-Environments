"""Tests for the FastAPI REST API."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from src.api.app import app, configure
from src.governance.config import GovernanceConfig
from src.ingestion.store import DecisionStore
from tests.conftest import make_decision_batch
from src.governance.schema import CaseCategory


@pytest.fixture
def client():
    config = GovernanceConfig.default()
    store = DecisionStore()
    configure(config, store)
    return TestClient(app), store, config


# ── Health ─────────────────────────────────────────────────────────────────────

def test_health(client):
    tc, *_ = client
    resp = tc.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ── Ingestion ──────────────────────────────────────────────────────────────────

def test_ingest_single_decision(client):
    tc, store, _ = client
    resp = tc.post("/decisions", json={
        "case_id": "C001",
        "category": "billing_dispute",
        "outcome": "resolved",
        "confidence": 0.88,
        "agent_version": "v1.0",
        "processing_time_ms": 450.0,
    })
    assert resp.status_code == 201
    body = resp.json()
    assert body["accepted"] == 1
    assert body["rejected"] == 0
    assert store.total_count() == 1


def test_ingest_unknown_category_auto_categorizes(client):
    tc, store, _ = client
    resp = tc.post("/decisions", json={
        "case_id": "C002",
        "category": "unknown",
        "outcome": "resolved",
        "confidence": 0.80,
        "agent_version": "v1.0",
        "processing_time_ms": 300.0,
        "case_text": "Customer is disputing a billing charge on their invoice",
    })
    assert resp.status_code == 201
    assert resp.json()["accepted"] == 1


def test_ingest_invalid_outcome_returns_422(client):
    tc, *_ = client
    resp = tc.post("/decisions", json={
        "case_id": "C003",
        "category": "routine",
        "outcome": "INVALID_OUTCOME",
        "confidence": 0.80,
        "agent_version": "v1.0",
        "processing_time_ms": 300.0,
    })
    assert resp.status_code == 422


def test_ingest_confidence_out_of_range_returns_422(client):
    tc, *_ = client
    resp = tc.post("/decisions", json={
        "case_id": "C004",
        "category": "routine",
        "outcome": "resolved",
        "confidence": 1.5,  # invalid
        "agent_version": "v1.0",
        "processing_time_ms": 300.0,
    })
    assert resp.status_code == 422


def test_ingest_batch(client):
    tc, store, _ = client
    decisions = [
        {
            "case_id": f"B{i:03d}",
            "category": "routine",
            "outcome": "resolved",
            "confidence": 0.85,
            "agent_version": "v1.0",
            "processing_time_ms": 400.0,
        }
        for i in range(10)
    ]
    resp = tc.post("/decisions/batch", json={"decisions": decisions})
    assert resp.status_code == 201
    assert resp.json()["accepted"] == 10
    assert store.total_count() == 10


def test_ingest_empty_batch_returns_422(client):
    tc, *_ = client
    resp = tc.post("/decisions/batch", json={"decisions": []})
    assert resp.status_code == 422


# ── Governance ─────────────────────────────────────────────────────────────────

def test_governance_status_empty_store_is_healthy(client):
    tc, *_ = client
    resp = tc.get("/governance/status")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
    assert resp.json()["total_decisions"] == 0


def test_governance_report_structure(client):
    tc, store, _ = client
    now = datetime.utcnow()
    decisions = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 10,
        resolve_p=0.83, error_p=0.04, escalate_p=0.10,
        base_time=now - timedelta(days=15),
    )
    store.store_decisions_batch(decisions)

    resp = tc.get("/governance/report")
    assert resp.status_code == 200
    body = resp.json()
    assert "status" in body
    assert "drift_results" in body
    assert "active_alerts" in body
    assert "total_decisions" in body
    assert body["total_decisions"] == 10


def test_get_alerts_empty(client):
    tc, *_ = client
    resp = tc.get("/governance/alerts")
    assert resp.status_code == 200
    assert resp.json() == []


def test_acknowledge_nonexistent_alert_returns_404(client):
    tc, *_ = client
    resp = tc.post("/governance/alerts/nonexistent-id/acknowledge")
    assert resp.status_code == 404


def test_resolve_rollback_when_none_active(client):
    tc, *_ = client
    resp = tc.post("/governance/rollback/resolve", json={"note": "reverted"})
    assert resp.status_code == 200
    assert resp.json()["resolved"] is False


# ── Metrics ────────────────────────────────────────────────────────────────────

def test_normal_metrics_empty_store(client):
    tc, *_ = client
    resp = tc.get("/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_decisions"] == 0
    assert body["overall_resolution_rate"] == 0.0


def test_normal_metrics_with_data(client):
    tc, store, _ = client
    now = datetime.utcnow()
    decisions = make_decision_batch(
        CaseCategory.ROUTINE, 20,
        resolve_p=0.85, error_p=0.05, escalate_p=0.07,
        base_time=now - timedelta(hours=12),
    )
    store.store_decisions_batch(decisions)

    resp = tc.get("/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_decisions"] == 20
    assert body["overall_resolution_rate"] > 0.5


# ── Round-trip: ingest + report ────────────────────────────────────────────────

def test_full_round_trip_ingest_and_report(client):
    tc, store, _ = client
    now = datetime.utcnow()

    # Ingest baseline decisions directly
    baseline = make_decision_batch(
        CaseCategory.BILLING_DISPUTE, 25,
        resolve_p=0.85, error_p=0.03, escalate_p=0.08,
        base_time=now - timedelta(days=15),
    )
    store.store_decisions_batch(baseline)

    # Ingest drifted recent decisions via API
    drifted = [
        {
            "case_id": f"DRIFT-{i:03d}",
            "category": "billing_dispute",
            "outcome": "error" if i % 3 == 0 else ("escalated" if i % 3 == 1 else "resolved"),
            "confidence": 0.50,
            "agent_version": "v1.1",
            "processing_time_ms": 900.0,
            "timestamp": (now - timedelta(hours=i)).isoformat(),
        }
        for i in range(8)
    ]
    resp = tc.post("/decisions/batch", json={"decisions": drifted})
    assert resp.status_code == 201
    assert resp.json()["accepted"] == 8

    report_resp = tc.get("/governance/report")
    assert report_resp.status_code == 200
    body = report_resp.json()
    assert body["total_decisions"] == 33

    billing_result = next(
        (r for r in body["drift_results"] if r["category"] == "billing_dispute"), None
    )
    assert billing_result is not None
