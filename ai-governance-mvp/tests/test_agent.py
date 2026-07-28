"""Unit tests for GovernanceAgent (src/governance/agent.py).

Covers:
- Parser-tier decide() with mock generate_fn
- decide_and_ingest() stores a decision in the store
- StructuredOutputError propagates and increments error_count
- Stats properties: call_count, error_count, error_rate, tier
- with_ingestor() is non-mutating
- make_agent() factory
- from_outlines() raises ImportError when outlines not installed
- from_instructor() raises ImportError when instructor not installed
- _build_prompt fallback when template has unknown keys
- Decide without ingestor raises RuntimeError on decide_and_ingest()
"""
from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.governance.agent import GovernanceAgent, make_agent
from src.governance.config import GovernanceConfig
from src.governance.schema import AgentDecision
from src.governance.structured import (
    GovernanceDecision,
    StructuredOutputError,
    _INSTRUCTOR_AVAILABLE,
    _OUTLINES_AVAILABLE,
)
from src.ingestion.ingestor import DecisionIngestor
from src.ingestion.store import DecisionStore


# ── Helpers ────────────────────────────────────────────────────────────────────

_VALID_JSON = json.dumps({
    "case_category": "billing_dispute",
    "risk_level": "high",
    "decision": "Refund the duplicate charge.",
    "confidence": 0.91,
    "flags": ["duplicate_charge"],
})

_INVALID_JSON = "Sorry, I cannot help with that."


def _make_agent(generate_fn=None, with_store: bool = False) -> GovernanceAgent:
    cfg = GovernanceConfig.default()
    fn = generate_fn or (lambda _p: _VALID_JSON)
    if with_store:
        store = DecisionStore()
        ingestor = DecisionIngestor(store, cfg)
        return GovernanceAgent(generate_fn=fn, config=cfg, ingestor=ingestor), store
    return GovernanceAgent(generate_fn=fn, config=cfg)


# ── Basic decide() ─────────────────────────────────────────────────────────────

class TestDecide:
    def test_returns_governance_decision(self):
        agent = _make_agent()
        result = agent.decide("Customer billed twice.")
        assert isinstance(result, GovernanceDecision)

    def test_parsed_fields_correct(self):
        agent = _make_agent()
        gd = agent.decide("Customer billed twice.")
        assert gd.case_category == "billing_dispute"
        assert gd.risk_level == "high"
        assert gd.confidence == pytest.approx(0.91)
        assert "duplicate_charge" in gd.flags

    def test_case_id_passed_through_prompt(self):
        captured = []
        def fn(prompt: str) -> str:
            captured.append(prompt)
            return _VALID_JSON
        agent = GovernanceAgent(generate_fn=fn, config=GovernanceConfig.default())
        agent.decide("Some text", case_id="CASE-999")
        assert len(captured) == 1
        assert "Some text" in captured[0]

    def test_extra_context_merged_into_prompt(self):
        captured = []
        template = "Case: {case_text}\nExtra: {extra_key}"
        def fn(prompt: str) -> str:
            captured.append(prompt)
            return _VALID_JSON
        agent = GovernanceAgent(
            generate_fn=fn,
            config=GovernanceConfig.default(),
            prompt_template=template,
        )
        agent.decide("text", extra_context={"extra_key": "VALUE"})
        assert "Extra: VALUE" in captured[0]

    def test_invalid_json_raises_structured_output_error(self):
        agent = _make_agent(generate_fn=lambda _: _INVALID_JSON)
        with pytest.raises(StructuredOutputError):
            agent.decide("Some case.")

    def test_error_propagates_not_swallowed(self):
        def boom(_prompt: str) -> str:
            raise RuntimeError("LLM unavailable")
        agent = _make_agent(generate_fn=boom)
        with pytest.raises(RuntimeError, match="LLM unavailable"):
            agent.decide("Case text.")


# ── Stats tracking ─────────────────────────────────────────────────────────────

class TestStats:
    def test_call_count_increments(self):
        agent = _make_agent()
        assert agent.call_count == 0
        agent.decide("Case 1.")
        agent.decide("Case 2.")
        assert agent.call_count == 2

    def test_error_count_increments_on_structured_output_error(self):
        agent = _make_agent(generate_fn=lambda _: _INVALID_JSON)
        assert agent.error_count == 0
        with pytest.raises(StructuredOutputError):
            agent.decide("Bad case.")
        assert agent.error_count == 1

    def test_error_count_does_not_increment_on_llm_exception(self):
        def boom(_: str) -> str:
            raise RuntimeError("network error")
        agent = _make_agent(generate_fn=boom)
        with pytest.raises(RuntimeError):
            agent.decide("Case.")
        assert agent.error_count == 0

    def test_error_rate_zero_with_no_calls(self):
        agent = _make_agent()
        assert agent.error_rate == 0.0

    def test_error_rate_correct(self):
        results = [_VALID_JSON, _INVALID_JSON, _VALID_JSON, _INVALID_JSON]
        idx = [0]
        def fn(_: str) -> str:
            r = results[idx[0]]
            idx[0] += 1
            return r
        agent = _make_agent(generate_fn=fn)
        agent.decide("case 1")
        with pytest.raises(StructuredOutputError):
            agent.decide("case 2")
        agent.decide("case 3")
        with pytest.raises(StructuredOutputError):
            agent.decide("case 4")
        assert agent.call_count == 4
        assert agent.error_count == 2
        assert agent.error_rate == pytest.approx(0.5)

    def test_tier_is_parser_by_default(self):
        agent = _make_agent()
        assert agent.tier == "parser"


# ── decide_and_ingest() ────────────────────────────────────────────────────────

class TestDecideAndIngest:
    def test_returns_agent_decision(self):
        agent, store = _make_agent(with_store=True)
        result = agent.decide_and_ingest("Customer billed twice.", case_id="CASE-001")
        assert isinstance(result, AgentDecision)

    def test_decision_stored_in_store(self):
        agent, store = _make_agent(with_store=True)
        agent.decide_and_ingest("Customer billed twice.", case_id="CASE-001")
        decisions = store.get_all_recent(limit=10)
        assert len(decisions) == 1
        assert decisions[0].case_id == "CASE-001"

    def test_agent_version_propagated(self):
        agent, store = _make_agent(with_store=True)
        agent.decide_and_ingest("Case text.", case_id="CASE-002", agent_version="v2.0")
        decisions = store.get_all_recent(limit=10)
        assert decisions[0].agent_version == "v2.0"

    def test_raises_without_ingestor(self):
        agent = _make_agent()
        with pytest.raises(RuntimeError, match="ingestor"):
            agent.decide_and_ingest("Some case.", case_id="CASE-X")

    def test_processing_time_recorded(self):
        agent, store = _make_agent(with_store=True)
        agent.decide_and_ingest("Case.", case_id="CASE-003")
        decisions = store.get_all_recent(limit=10)
        assert decisions[0].processing_time_ms >= 0.0


# ── with_ingestor() ────────────────────────────────────────────────────────────

class TestWithIngestor:
    def test_returns_new_agent_instance(self):
        agent = _make_agent()
        store = DecisionStore()
        cfg = GovernanceConfig.default()
        ingestor = DecisionIngestor(store, cfg)
        new_agent = agent.with_ingestor(ingestor)
        assert new_agent is not agent

    def test_original_agent_unchanged(self):
        agent = _make_agent()
        store = DecisionStore()
        cfg = GovernanceConfig.default()
        ingestor = DecisionIngestor(store, cfg)
        agent.with_ingestor(ingestor)
        with pytest.raises(RuntimeError, match="ingestor"):
            agent.decide_and_ingest("Case.", case_id="X")

    def test_new_agent_can_ingest(self):
        agent = _make_agent()
        store = DecisionStore()
        cfg = GovernanceConfig.default()
        ingestor = DecisionIngestor(store, cfg)
        new_agent = agent.with_ingestor(ingestor)
        result = new_agent.decide_and_ingest("Case.", case_id="CASE-010")
        assert isinstance(result, AgentDecision)

    def test_tier_preserved_on_with_ingestor(self):
        agent = _make_agent()
        store = DecisionStore()
        cfg = GovernanceConfig.default()
        ingestor = DecisionIngestor(store, cfg)
        new_agent = agent.with_ingestor(ingestor)
        assert new_agent.tier == agent.tier


# ── make_agent() factory ───────────────────────────────────────────────────────

class TestMakeAgent:
    def test_returns_governance_agent(self):
        agent = make_agent(lambda _: _VALID_JSON)
        assert isinstance(agent, GovernanceAgent)

    def test_tier_is_parser(self):
        agent = make_agent(lambda _: _VALID_JSON)
        assert agent.tier == "parser"

    def test_with_store_creates_ingestor(self):
        store = DecisionStore()
        agent = make_agent(lambda _: _VALID_JSON, store=store)
        result = agent.decide_and_ingest("Case.", case_id="MK-001")
        assert isinstance(result, AgentDecision)

    def test_without_store_no_ingestor(self):
        agent = make_agent(lambda _: _VALID_JSON)
        with pytest.raises(RuntimeError, match="ingestor"):
            agent.decide_and_ingest("Case.", case_id="MK-X")

    def test_uses_provided_config(self):
        cfg = GovernanceConfig.default()
        agent = make_agent(lambda _: _VALID_JSON, config=cfg)
        assert agent._config is cfg


# ── from_outlines() ────────────────────────────────────────────────────────────

class TestFromOutlines:
    def test_raises_import_error_when_outlines_unavailable(self):
        with patch("src.governance.agent._OUTLINES_AVAILABLE", False):
            with pytest.raises(ImportError, match="outlines"):
                GovernanceAgent.from_outlines(
                    outlines_model=MagicMock(),
                    config=GovernanceConfig.default(),
                )

    @pytest.mark.skipif(not _OUTLINES_AVAILABLE, reason="outlines with generate API not installed")
    def test_tier_is_outlines_when_available(self):
        import outlines
        mock_model = MagicMock()
        mock_generator = MagicMock(return_value={"case_category": "routine",
                                                  "risk_level": "low",
                                                  "decision": "Handle normally.",
                                                  "confidence": 0.8,
                                                  "flags": []})
        patch_target = "outlines.generate.json" if hasattr(outlines, "generate") else "outlines.generator"
        with patch(patch_target, return_value=mock_generator):
            agent = GovernanceAgent.from_outlines(mock_model, GovernanceConfig.default())
        assert agent.tier == "outlines"


# ── from_instructor() ─────────────────────────────────────────────────────────

class TestFromInstructor:
    def test_raises_import_error_when_instructor_unavailable(self):
        with patch("src.governance.agent._INSTRUCTOR_AVAILABLE", False):
            with pytest.raises(ImportError, match="instructor"):
                GovernanceAgent.from_instructor(
                    instructor_client=MagicMock(),
                    model="gpt-4o",
                    config=GovernanceConfig.default(),
                )

    @pytest.mark.skipif(not _INSTRUCTOR_AVAILABLE, reason="instructor not installed")
    def test_tier_is_instructor_when_available(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="Handle normally.",
            confidence=0.8,
            flags=[],
        )
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = gd
        agent = GovernanceAgent.from_instructor(mock_client, "gpt-4o", GovernanceConfig.default())
        assert agent.tier == "instructor"


# ── Prompt building ────────────────────────────────────────────────────────────

class TestPromptBuilding:
    def test_prompt_contains_case_text(self):
        captured = []
        def fn(prompt: str) -> str:
            captured.append(prompt)
            return _VALID_JSON
        agent = GovernanceAgent(generate_fn=fn, config=GovernanceConfig.default())
        agent.decide("Unique case text 12345")
        assert "Unique case text 12345" in captured[0]

    def test_fallback_when_template_missing_key(self):
        captured = []
        bad_template = "Process: {case_text} | Extra: {missing_key}"
        def fn(prompt: str) -> str:
            captured.append(prompt)
            return _VALID_JSON
        agent = GovernanceAgent(
            generate_fn=fn,
            config=GovernanceConfig.default(),
            prompt_template=bad_template,
        )
        agent.decide("Fallback text.")
        assert "Fallback text." in captured[0]

    def test_custom_template_used(self):
        captured = []
        template = "CUSTOM TEMPLATE: {case_text}"
        def fn(prompt: str) -> str:
            captured.append(prompt)
            return _VALID_JSON
        agent = GovernanceAgent(
            generate_fn=fn,
            config=GovernanceConfig.default(),
            prompt_template=template,
        )
        agent.decide("My case.")
        assert captured[0].startswith("CUSTOM TEMPLATE:")


# ── Confidence clamping edge cases ─────────────────────────────────────────────

class TestConfidenceClamping:
    def test_confidence_above_one_clamped(self):
        raw = json.dumps({
            "case_category": "routine",
            "risk_level": "low",
            "decision": "Handled.",
            "confidence": 1.5,
            "flags": [],
        })
        agent = _make_agent(generate_fn=lambda _: raw)
        gd = agent.decide("test")
        assert gd.confidence == pytest.approx(1.0)

    def test_confidence_below_zero_clamped(self):
        raw = json.dumps({
            "case_category": "routine",
            "risk_level": "low",
            "decision": "Handled.",
            "confidence": -0.3,
            "flags": [],
        })
        agent = _make_agent(generate_fn=lambda _: raw)
        gd = agent.decide("test")
        assert gd.confidence == pytest.approx(0.0)
