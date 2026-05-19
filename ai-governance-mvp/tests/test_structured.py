"""Unit tests for GovernanceDecision schema and StructuredOutputParser."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from src.governance.structured import (
    GovernanceDecision,
    StructuredOutputError,
    StructuredOutputParser,
    get_parser,
)


# ── GovernanceDecision model ───────────────────────────────────────────────────

class TestGovernanceDecision:

    def test_valid_minimal(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="Auto-resolved.",
            confidence=0.95,
            flags=[],
        )
        assert gd.case_category == "routine"
        assert gd.risk_level == "low"
        assert gd.confidence == 0.95
        assert gd.flags == []

    def test_category_normalisation_spaces(self):
        gd = GovernanceDecision(
            case_category="Billing Dispute",
            risk_level="high",
            decision="Refund issued.",
            confidence=0.9,
        )
        assert gd.case_category == "billing_dispute"

    def test_category_normalisation_dashes(self):
        gd = GovernanceDecision(
            case_category="policy-sensitive",
            risk_level="medium",
            decision="Escalate.",
            confidence=0.7,
        )
        assert gd.case_category == "policy_sensitive"

    def test_category_normalisation_mixed_case_and_dash(self):
        gd = GovernanceDecision(
            case_category="Fraud-Claim",
            risk_level="critical",
            decision="Block account.",
            confidence=0.99,
        )
        assert gd.case_category == "fraud_claim"

    def test_confidence_clamp_above_one(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="ok",
            confidence=1.001,
        )
        assert gd.confidence == 1.0

    def test_confidence_clamp_below_zero(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="ok",
            confidence=-0.5,
        )
        assert gd.confidence == 0.0

    def test_confidence_zero_exact(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="ok",
            confidence=0.0,
        )
        assert gd.confidence == 0.0

    def test_confidence_one_exact(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="ok",
            confidence=1.0,
        )
        assert gd.confidence == 1.0

    def test_is_high_risk_true_for_high(self):
        gd = GovernanceDecision(
            case_category="billing_dispute",
            risk_level="high",
            decision="refund",
            confidence=0.8,
        )
        assert gd.is_high_risk is True

    def test_is_high_risk_true_for_critical(self):
        gd = GovernanceDecision(
            case_category="fraud_claim",
            risk_level="critical",
            decision="block",
            confidence=0.99,
        )
        assert gd.is_high_risk is True

    def test_is_high_risk_false_for_low(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="auto-resolve",
            confidence=0.9,
        )
        assert gd.is_high_risk is False

    def test_is_high_risk_false_for_medium(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="medium",
            decision="review",
            confidence=0.6,
        )
        assert gd.is_high_risk is False

    def test_flags_default_empty_list(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="ok",
            confidence=0.9,
        )
        assert gd.flags == []

    def test_flags_populated(self):
        gd = GovernanceDecision(
            case_category="billing_dispute",
            risk_level="high",
            decision="escalate",
            confidence=0.7,
            flags=["high_value", "repeat_dispute"],
        )
        assert "high_value" in gd.flags
        assert len(gd.flags) == 2

    def test_to_dict(self):
        gd = GovernanceDecision(
            case_category="routine",
            risk_level="low",
            decision="ok",
            confidence=0.9,
            flags=["f1"],
        )
        d = gd.to_dict()
        assert d["case_category"] == "routine"
        assert d["confidence"] == 0.9
        assert d["flags"] == ["f1"]

    def test_invalid_risk_level_raises(self):
        with pytest.raises(ValidationError):
            GovernanceDecision(
                case_category="routine",
                risk_level="extreme",  # not in Literal
                decision="ok",
                confidence=0.9,
            )

    def test_missing_decision_raises(self):
        with pytest.raises(ValidationError):
            GovernanceDecision(
                case_category="routine",
                risk_level="low",
                confidence=0.9,
            )

    def test_empty_decision_raises(self):
        with pytest.raises(ValidationError):
            GovernanceDecision(
                case_category="routine",
                risk_level="low",
                decision="",
                confidence=0.9,
            )

    def test_model_validate_from_dict(self):
        d = {
            "case_category": "fraud_claim",
            "risk_level": "critical",
            "decision": "block",
            "confidence": 0.99,
            "flags": ["suspicious_ip"],
        }
        gd = GovernanceDecision.model_validate(d)
        assert gd.case_category == "fraud_claim"
        assert gd.risk_level == "critical"


# ── StructuredOutputParser ─────────────────────────────────────────────────────

_VALID_DICT = {
    "case_category": "billing_dispute",
    "risk_level": "high",
    "decision": "Issue refund.",
    "confidence": 0.92,
    "flags": ["duplicate_charge"],
}


class TestStructuredOutputParser:

    @pytest.fixture
    def parser(self):
        return StructuredOutputParser()

    def test_parse_pure_json_string(self, parser):
        raw = json.dumps(_VALID_DICT)
        gd = parser.parse(raw)
        assert gd.case_category == "billing_dispute"
        assert gd.risk_level == "high"

    def test_parse_json_in_mixed_text(self, parser):
        raw = f"Agent output below:\n{json.dumps(_VALID_DICT)}\nEnd."
        gd = parser.parse(raw)
        assert gd.case_category == "billing_dispute"

    def test_parse_json_with_leading_prose(self, parser):
        raw = "The decision is as follows: " + json.dumps(_VALID_DICT)
        gd = parser.parse(raw)
        assert isinstance(gd, GovernanceDecision)

    def test_parse_empty_string_raises(self, parser):
        with pytest.raises(StructuredOutputError):
            parser.parse("")

    def test_parse_no_json_raises(self, parser):
        with pytest.raises(StructuredOutputError) as exc_info:
            parser.parse("The agent decided to escalate the case.")
        assert "No JSON object" in str(exc_info.value)

    def test_parse_invalid_schema_raises(self, parser):
        bad = {"case_category": "routine", "risk_level": "bad_level", "decision": "ok", "confidence": 0.9}
        with pytest.raises(StructuredOutputError) as exc_info:
            parser.parse(json.dumps(bad))
        assert "validation" in str(exc_info.value).lower()

    def test_parse_missing_required_field_raises(self, parser):
        incomplete = {k: v for k, v in _VALID_DICT.items() if k != "decision"}
        with pytest.raises(StructuredOutputError):
            parser.parse(json.dumps(incomplete))

    def test_parse_or_none_valid(self, parser):
        raw = json.dumps(_VALID_DICT)
        result = parser.parse_or_none(raw)
        assert result is not None
        assert result.case_category == "billing_dispute"

    def test_parse_or_none_invalid_returns_none(self, parser):
        result = parser.parse_or_none("no json here at all")
        assert result is None

    def test_parse_or_none_bad_schema_returns_none(self, parser):
        bad = {"case_category": "routine", "risk_level": "INVALID", "decision": "ok", "confidence": 0.5}
        result = parser.parse_or_none(json.dumps(bad))
        assert result is None

    def test_validate_dict_valid(self, parser):
        gd = parser.validate(_VALID_DICT)
        assert isinstance(gd, GovernanceDecision)

    def test_validate_dict_invalid_raises(self, parser):
        bad = {"case_category": "routine"}
        with pytest.raises(StructuredOutputError):
            parser.validate(bad)

    def test_json_schema_property(self, parser):
        schema = parser.json_schema
        assert isinstance(schema, dict)
        assert "properties" in schema

    def test_backend_attribute_set(self, parser):
        assert parser.backend in ("outlines", "instructor", "pydantic")

    def test_parse_handles_confidence_clamping(self, parser):
        d = dict(_VALID_DICT)
        d["confidence"] = 1.001  # above 1.0 — should clamp, not raise
        gd = parser.parse(json.dumps(d))
        assert gd.confidence == 1.0

    def test_parse_normalises_category(self, parser):
        d = dict(_VALID_DICT)
        d["case_category"] = "Billing Dispute"
        gd = parser.parse(json.dumps(d))
        assert gd.case_category == "billing_dispute"

    def test_get_parser_returns_singleton(self):
        p1 = get_parser()
        p2 = get_parser()
        assert p1 is p2

    def test_parse_nested_json_not_confused(self, parser):
        """Ensure nested objects inside decision field don't break extraction."""
        d = dict(_VALID_DICT)
        d["decision"] = "Refund amount: $100"
        d["flags"] = ["high_value", "repeat"]
        gd = parser.parse(json.dumps(d))
        assert gd.confidence == _VALID_DICT["confidence"]


# ── StructuredOutputError ──────────────────────────────────────────────────────

class TestStructuredOutputError:

    def test_str_without_validation_errors(self):
        err = StructuredOutputError("No JSON found", raw_output="abc")
        assert "No JSON found" in str(err)

    def test_str_with_validation_errors(self):
        err = StructuredOutputError(
            "Validation failed",
            raw_output="{}",
            validation_errors="field required",
        )
        assert "validation" in str(err).lower()
        assert "field required" in str(err)

    def test_raw_output_preserved(self):
        raw = '{"bad": true}'
        err = StructuredOutputError("msg", raw_output=raw)
        assert err.raw_output == raw

    def test_validation_errors_preserved(self):
        err = StructuredOutputError("msg", validation_errors="type_error")
        assert err.validation_errors == "type_error"

    def test_is_subclass_of_value_error(self):
        err = StructuredOutputError("test")
        assert isinstance(err, ValueError)
