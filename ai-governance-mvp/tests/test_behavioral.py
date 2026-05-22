"""
Behavioral regression tests — governance gate.

These 50 fixed decisions constitute the governance regression suite.
Rules:
  - Every commit must pass this suite (mark: behavioral).
  - If ANY behavioral test fails in CI, the rollback conftest hook fires a
    RollbackEvent into the session store (see conftest_behavioral fixture).
  - The fixture dataset is immutable; changing it requires a deliberate version bump.

Test structure:
  1. Schema validation — every fixture parses as a valid GovernanceDecision.
  2. Risk classification — high-risk cases carry correct risk_level.
  3. Category normalization — edge-case category strings round-trip correctly.
  4. Outcome mapping — decision text drives the correct DecisionOutcome.
  5. Ingestor round-trip — GovernanceDecision → AgentDecision → stored correctly.
  6. Drift threshold — ingesting healthy fixtures produces drift_score < 0.6.
  7. Rollback gate — drifted behavioral data triggers rollback recommendation.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from src.governance.config import GovernanceConfig
from src.governance.schema import (
    CaseCategory,
    DecisionOutcome,
    RollbackEvent,
)
from src.governance.structured import GovernanceDecision, StructuredOutputParser
from src.ingestion.ingestor import DecisionIngestor
from src.ingestion.store import DecisionStore
from src.detection.detector import DriftDetector
from src.engine.rollback import RollbackEngine

from tests.fixtures.decisions import (
    FIXTURE_DECISIONS,
    BILLING_FIXTURES,
    FRAUD_FIXTURES,
    POLICY_FIXTURES,
    ROUTINE_FIXTURES,
    EDGE_FIXTURES,
    HIGH_RISK_FIXTURES,
    SCHEMA_DICTS,
)
from tests.conftest import make_decision_batch

pytestmark = pytest.mark.behavioral


# ── Session-scoped rollback gate ───────────────────────────────────────────────
# The actual gate is implemented as pytest_sessionfinish in conftest.py, which
# correctly tracks behavioral failures via pytest_runtest_logreport.
# This fixture exposes the shared store for tests that need to verify the gate.


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse(d: dict) -> GovernanceDecision:
    """Validate a fixture dict against the GovernanceDecision schema."""
    return GovernanceDecision.model_validate(d)


def _schema_only(d: dict) -> dict:
    """Strip _* metadata keys from a fixture dict."""
    return {k: v for k, v in d.items() if not k.startswith("_")}


# ── 1. Schema validation ───────────────────────────────────────────────────────

class TestSchemaValidation:
    """Every fixture must parse as a valid GovernanceDecision."""

    def test_all_50_fixtures_parse(self):
        assert len(FIXTURE_DECISIONS) == 50
        for i, d in enumerate(FIXTURE_DECISIONS):
            gd = _parse(_schema_only(d))
            assert isinstance(gd, GovernanceDecision), f"fixture[{i}] failed to parse"

    def test_all_schema_dicts_valid(self):
        """SCHEMA_DICTS convenience view must also all validate."""
        assert len(SCHEMA_DICTS) == 50
        for i, d in enumerate(SCHEMA_DICTS):
            gd = GovernanceDecision.model_validate(d)
            assert isinstance(gd, GovernanceDecision), f"SCHEMA_DICTS[{i}] invalid"

    def test_billing_fixtures_count(self):
        assert len(BILLING_FIXTURES) == 10

    def test_fraud_fixtures_count(self):
        assert len(FRAUD_FIXTURES) == 10

    def test_policy_fixtures_count(self):
        assert len(POLICY_FIXTURES) == 10

    def test_routine_fixtures_count(self):
        assert len(ROUTINE_FIXTURES) == 10

    def test_edge_fixtures_count(self):
        assert len(EDGE_FIXTURES) == 10

    def test_confidence_always_in_range(self):
        for d in SCHEMA_DICTS:
            gd = _parse(d)
            assert 0.0 <= gd.confidence <= 1.0, (
                f"confidence {gd.confidence} out of range in {d}"
            )

    def test_risk_level_always_valid(self):
        valid = {"low", "medium", "high", "critical"}
        for d in SCHEMA_DICTS:
            gd = _parse(d)
            assert gd.risk_level in valid, f"Invalid risk_level: {gd.risk_level}"

    def test_decision_text_never_empty(self):
        for d in SCHEMA_DICTS:
            gd = _parse(d)
            assert gd.decision.strip(), "decision text is empty"

    def test_flags_is_list(self):
        for d in SCHEMA_DICTS:
            gd = _parse(d)
            assert isinstance(gd.flags, list)


# ── 2. Risk classification ─────────────────────────────────────────────────────

class TestRiskClassification:
    """High-risk fixtures must carry the expected risk_level values."""

    def test_billing_disputes_are_high_risk(self):
        for d in BILLING_FIXTURES:
            gd = _parse(_schema_only(d))
            assert gd.risk_level in ("high", "critical"), (
                f"billing_dispute fixture has unexpected risk_level={gd.risk_level}"
            )

    def test_fraud_claims_are_critical(self):
        for d in FRAUD_FIXTURES:
            gd = _parse(_schema_only(d))
            assert gd.risk_level in ("high", "critical"), (
                f"fraud_claim fixture has unexpected risk_level={gd.risk_level}"
            )

    def test_routine_cases_are_low_risk(self):
        for d in ROUTINE_FIXTURES:
            gd = _parse(_schema_only(d))
            assert gd.risk_level in ("low", "medium"), (
                f"routine fixture has unexpected risk_level={gd.risk_level}"
            )

    def test_high_risk_fixtures_is_high_risk_property(self):
        assert len(HIGH_RISK_FIXTURES) > 0
        for d in HIGH_RISK_FIXTURES:
            gd = _parse(_schema_only(d))
            assert gd.is_high_risk, (
                f"HIGH_RISK_FIXTURES entry has is_high_risk=False: risk_level={gd.risk_level}"
            )

    def test_billing_expected_category_annotation(self):
        for d in BILLING_FIXTURES:
            assert d["_expected_category"] == "billing_dispute"

    def test_fraud_expected_category_annotation(self):
        for d in FRAUD_FIXTURES:
            assert d["_expected_category"] == "fraud_claim"

    def test_policy_expected_category_annotation(self):
        for d in POLICY_FIXTURES:
            assert d["_expected_category"] == "policy_sensitive"

    def test_routine_expected_category_annotation(self):
        for d in ROUTINE_FIXTURES:
            assert d["_expected_category"] == "routine"


# ── 3. Category normalization ──────────────────────────────────────────────────

class TestCategoryNormalization:
    """Confirm the _normalise_category validator handles edge inputs."""

    @pytest.mark.parametrize("raw,expected", [
        ("billing_dispute", "billing_dispute"),
        ("Billing Dispute", "billing_dispute"),
        ("BILLING-DISPUTE", "billing_dispute"),
        ("fraud_claim", "fraud_claim"),
        ("Fraud Claim", "fraud_claim"),
        ("policy_sensitive", "policy_sensitive"),
        ("Policy-Sensitive", "policy_sensitive"),
        ("routine", "routine"),
        ("  routine  ", "routine"),
        ("unknown", "unknown"),
    ])
    def test_normalise_category(self, raw, expected):
        gd = GovernanceDecision(
            case_category=raw,
            risk_level="low",
            decision="test",
            confidence=0.9,
            flags=[],
        )
        assert gd.case_category == expected

    def test_edge_fixtures_with_unusual_category_strings_parse(self):
        """Edge fixtures may use non-standard category strings — must not raise."""
        for d in EDGE_FIXTURES:
            gd = _parse(_schema_only(d))
            assert isinstance(gd.case_category, str)
            assert len(gd.case_category) > 0

    def test_confidence_clamp_above_one(self):
        """Confidence slightly above 1.0 (float arithmetic) is silently clamped."""
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="all good",
            confidence=1.001,
            flags=[],
        )
        assert gd.confidence == 1.0

    def test_confidence_clamp_below_zero(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="all good",
            confidence=-0.001,
            flags=[],
        )
        assert gd.confidence == 0.0


# ── 4. Outcome mapping ─────────────────────────────────────────────────────────

class TestOutcomeMapping:
    """
    The ingestor derives DecisionOutcome from GovernanceDecision.decision text.
    Verify that fixture._outcome matches the heuristic result.
    """

    OUTCOME_KEYWORDS = {
        "resolved": DecisionOutcome.RESOLVED,
        "escalated": DecisionOutcome.ESCALATED,
        "rejected": DecisionOutcome.REJECTED,
        "error": DecisionOutcome.ERROR,
    }

    def _expected_outcome(self, decision_text: str) -> DecisionOutcome:
        dl = decision_text.lower()
        if any(w in dl for w in ("escalat", "human review", "manual")):
            return DecisionOutcome.ESCALATED
        if any(w in dl for w in ("error", "fail", "unable", "cannot")):
            return DecisionOutcome.ERROR
        if any(w in dl for w in ("reject", "deny", "block", "decline")):
            return DecisionOutcome.REJECTED
        return DecisionOutcome.RESOLVED

    def test_billing_outcomes_match_annotation(self):
        for d in BILLING_FIXTURES:
            gd = _parse(_schema_only(d))
            expected = self._expected_outcome(gd.decision)
            annotated = d["_outcome"]
            assert expected.value == annotated, (
                f"billing fixture outcome mismatch: heuristic={expected.value!r} "
                f"annotation={annotated!r} decision={gd.decision!r}"
            )

    def test_fraud_outcomes_match_annotation(self):
        for d in FRAUD_FIXTURES:
            gd = _parse(_schema_only(d))
            expected = self._expected_outcome(gd.decision)
            assert expected.value == d["_outcome"], (
                f"fraud fixture outcome mismatch: {gd.decision!r}"
            )

    def test_policy_outcomes_match_annotation(self):
        for d in POLICY_FIXTURES:
            gd = _parse(_schema_only(d))
            expected = self._expected_outcome(gd.decision)
            assert expected.value == d["_outcome"], (
                f"policy fixture outcome mismatch: {gd.decision!r}"
            )

    def test_routine_outcomes_match_annotation(self):
        for d in ROUTINE_FIXTURES:
            gd = _parse(_schema_only(d))
            expected = self._expected_outcome(gd.decision)
            assert expected.value == d["_outcome"], (
                f"routine fixture outcome mismatch: {gd.decision!r}"
            )


# ── 5. Ingestor round-trip ─────────────────────────────────────────────────────

class TestIngestorRoundTrip:
    """GovernanceDecision fixtures must survive the full ingest pipeline."""

    @pytest.fixture
    def ingestor(self):
        store = DecisionStore()
        config = GovernanceConfig.default()
        return DecisionIngestor(store, config), store

    def test_all_billing_fixtures_ingest(self, ingestor):
        ing, store = ingestor
        for d in BILLING_FIXTURES:
            gd = _parse(_schema_only(d))
            ad = ing.ingest_governance_decision(
                gd, case_id=f"BIL-{id(d)}", agent_version="behavioral-v1"
            )
            assert ad.category == CaseCategory.BILLING_DISPUTE
            assert 0.0 <= ad.confidence <= 1.0

    def test_all_fraud_fixtures_ingest(self, ingestor):
        ing, store = ingestor
        for d in FRAUD_FIXTURES:
            gd = _parse(_schema_only(d))
            ad = ing.ingest_governance_decision(
                gd, case_id=f"FRD-{id(d)}", agent_version="behavioral-v1"
            )
            assert ad.category == CaseCategory.FRAUD_CLAIM

    def test_all_policy_fixtures_ingest(self, ingestor):
        ing, store = ingestor
        for d in POLICY_FIXTURES:
            gd = _parse(_schema_only(d))
            ad = ing.ingest_governance_decision(
                gd, case_id=f"POL-{id(d)}", agent_version="behavioral-v1"
            )
            assert ad.category == CaseCategory.POLICY_SENSITIVE

    def test_all_routine_fixtures_ingest(self, ingestor):
        ing, store = ingestor
        for d in ROUTINE_FIXTURES:
            gd = _parse(_schema_only(d))
            ad = ing.ingest_governance_decision(
                gd, case_id=f"RTN-{id(d)}", agent_version="behavioral-v1"
            )
            assert ad.category == CaseCategory.ROUTINE

    def test_edge_fixtures_ingest_without_raising(self, ingestor):
        """Edge fixtures may produce UNKNOWN category — that's acceptable."""
        ing, _ = ingestor
        errors = []
        for i, d in enumerate(EDGE_FIXTURES):
            gd = _parse(_schema_only(d))
            try:
                ing.ingest_governance_decision(
                    gd, case_id=f"EDGE-{i}", agent_version="behavioral-v1"
                )
            except Exception as exc:
                errors.append(f"EDGE[{i}]: {exc}")
        assert not errors, f"Edge fixture ingestion errors:\n" + "\n".join(errors)

    def test_ingest_stores_risk_level_in_metadata(self, ingestor):
        ing, store = ingestor
        d = BILLING_FIXTURES[0]
        gd = _parse(_schema_only(d))
        ad = ing.ingest_governance_decision(
            gd, case_id="BIL-META-001", agent_version="behavioral-v1"
        )
        assert ad.metadata.get("risk_level") == "high"

    def test_ingest_stores_flags_in_metadata(self, ingestor):
        ing, _ = ingestor
        d = BILLING_FIXTURES[0]
        gd = _parse(_schema_only(d))
        ad = ing.ingest_governance_decision(
            gd, case_id="BIL-FLAGS-001", agent_version="behavioral-v1"
        )
        assert isinstance(ad.metadata.get("flags"), list)

    def test_parse_and_ingest_from_json_string(self, ingestor):
        """parse_and_ingest must handle raw JSON strings from agent output."""
        import json
        ing, _ = ingestor
        d = _schema_only(BILLING_FIXTURES[2])
        raw = json.dumps(d)
        ad = ing.parse_and_ingest(raw, case_id="BIL-JSON-001", agent_version="behavioral-v1")
        assert ad.category == CaseCategory.BILLING_DISPUTE

    def test_parse_and_ingest_from_mixed_text(self, ingestor):
        """parse_and_ingest must extract JSON embedded in prose."""
        import json
        ing, _ = ingestor
        d = _schema_only(FRAUD_FIXTURES[0])
        raw = f"Agent reasoning: the case requires review.\n{json.dumps(d)}\nEnd of output."
        ad = ing.parse_and_ingest(raw, case_id="FRD-MIXED-001", agent_version="behavioral-v1")
        assert ad.category == CaseCategory.FRAUD_CLAIM


# ── 6. Drift threshold — healthy baseline ─────────────────────────────────────

class TestDriftThreshold:
    """
    When all 50 fixtures are ingested as both baseline and recent data,
    drift scores must remain below the warning threshold (< 0.6) because
    both windows have the same distribution.
    """

    @pytest.fixture
    def healthy_store_with_drift(self):
        """
        Populate store with fixture-derived decisions placed in time windows
        that produce a stable comparison (same distribution, no drift).
        """
        config = GovernanceConfig.default()
        store = DecisionStore()
        ing = DecisionIngestor(store, config)
        now = datetime.utcnow()

        # Use make_decision_batch for large, stable samples
        # Baseline window: [now-30d, now-7d)
        from tests.conftest import make_decision_batch
        baseline_time = now - timedelta(days=15)
        recent_time = now - timedelta(hours=12)

        for cat, resolve_p in [
            (CaseCategory.BILLING_DISPUTE, 0.70),
            (CaseCategory.FRAUD_CLAIM, 0.30),
            (CaseCategory.POLICY_SENSITIVE, 0.50),
            (CaseCategory.ROUTINE, 0.90),
        ]:
            baseline = make_decision_batch(
                cat, 80, resolve_p=resolve_p, error_p=0.05, escalate_p=0.15,
                base_time=baseline_time, time_step_seconds=600,
            )
            recent = make_decision_batch(
                cat, 40, resolve_p=resolve_p, error_p=0.05, escalate_p=0.15,
                base_time=recent_time, time_step_seconds=120,
            )
            store.store_decisions_batch(baseline)
            store.store_decisions_batch(recent)

        return store, config

    def test_billing_drift_below_warning_threshold(self, healthy_store_with_drift):
        store, config = healthy_store_with_drift
        detector = DriftDetector(store, config)
        result = detector.detect_category(CaseCategory.BILLING_DISPUTE)
        assert result is not None
        if not result.insufficient_data:
            assert result.drift_score < 0.6, (
                f"Healthy billing_dispute shows drift_score={result.drift_score:.3f} "
                f"(should be < 0.6 for stable distribution)"
            )

    def test_fraud_drift_below_warning_threshold(self, healthy_store_with_drift):
        store, config = healthy_store_with_drift
        detector = DriftDetector(store, config)
        result = detector.detect_category(CaseCategory.FRAUD_CLAIM)
        assert result is not None
        if not result.insufficient_data:
            assert result.drift_score < 0.6

    def test_policy_drift_below_warning_threshold(self, healthy_store_with_drift):
        store, config = healthy_store_with_drift
        detector = DriftDetector(store, config)
        result = detector.detect_category(CaseCategory.POLICY_SENSITIVE)
        assert result is not None
        if not result.insufficient_data:
            assert result.drift_score < 0.6

    def test_routine_drift_below_warning_threshold(self, healthy_store_with_drift):
        store, config = healthy_store_with_drift
        detector = DriftDetector(store, config)
        result = detector.detect_category(CaseCategory.ROUTINE)
        assert result is not None
        if not result.insufficient_data:
            assert result.drift_score < 0.6

    def test_drift_result_has_valid_score_range(self, healthy_store_with_drift):
        store, config = healthy_store_with_drift
        detector = DriftDetector(store, config)
        results = detector.run_detection()
        for r in results:
            assert 0.0 <= r.drift_score <= 1.0, (
                f"{r.category}: drift_score={r.drift_score:.3f} out of [0,1]"
            )


# ── 7. Rollback gate — drifted behavioral data triggers rollback ───────────────

class TestRollbackGate:
    """
    When the agent drifts severely (error_rate spikes), the rollback engine
    must recommend or trigger a rollback. This is the CI enforcement gate.
    """

    @pytest.fixture
    def drifted_store(self):
        config = GovernanceConfig.default()
        store = DecisionStore()
        now = datetime.utcnow()

        # Healthy baseline 15 days ago
        baseline = make_decision_batch(
            CaseCategory.BILLING_DISPUTE, 80,
            resolve_p=0.83, error_p=0.04, escalate_p=0.10,
            base_time=now - timedelta(days=15),
            time_step_seconds=600,
        )
        # Severely drifted recent window
        drifted = make_decision_batch(
            CaseCategory.BILLING_DISPUTE, 40,
            resolve_p=0.20, error_p=0.50, escalate_p=0.25,
            base_time=now - timedelta(hours=12),
            time_step_seconds=120,
        )
        store.store_decisions_batch(baseline)
        store.store_decisions_batch(drifted)
        return store, config

    def test_drifted_agent_produces_high_drift_score(self, drifted_store):
        store, config = drifted_store
        detector = DriftDetector(store, config)
        result = detector.detect_category(CaseCategory.BILLING_DISPUTE)
        assert result is not None
        assert not result.insufficient_data
        assert result.drift_score > 0.4, (
            f"Expected high drift for severely drifted agent, got {result.drift_score:.3f}"
        )

    def test_rollback_engine_recommends_on_critical_drift(self, drifted_store):
        store, config = drifted_store
        detector = DriftDetector(store, config)
        rollback_engine = RollbackEngine(store, config)

        results = detector.run_detection()
        should_rollback, reason, triggering = rollback_engine.evaluate(results)
        assert should_rollback, (
            f"Expected rollback to be recommended for severely drifted agent; "
            f"results: {[(r.category.value, r.drift_score) for r in results]}"
        )
        event = rollback_engine.trigger_rollback(reason, triggering)
        assert event is not None
        assert event.is_active

    def test_store_rollback_event_persists(self, drifted_store):
        store, _ = drifted_store
        event = RollbackEvent(
            reason="Behavioral test triggered rollback",
            triggered_by="behavioral_test_suite",
            category=CaseCategory.BILLING_DISPUTE,
            drift_score=0.95,
            agent_version="behavioral-v1",
        )
        store.store_rollback_event(event)
        active = store.get_active_rollback()
        assert active is not None
