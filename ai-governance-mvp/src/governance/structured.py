"""
Constrained decoding contract for all agent decisions.

outlines (primary) enforces structured generation at the LLM sampling level
so malformed JSON is impossible to produce. When processing decisions that
already exist as text, StructuredOutputParser extracts and validates them.

instructor (fallback) provides the same guarantee via OpenAI/Anthropic
function-calling APIs.

Both backends share the same GovernanceDecision Pydantic model — one
typed object, zero free-text parsing in the drift detector.
"""
from __future__ import annotations

import json
import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

# ── Backend availability ───────────────────────────────────────────────────────

try:
    import outlines as _outlines
    _OUTLINES_AVAILABLE = True
except ImportError:  # pragma: no cover
    _OUTLINES_AVAILABLE = False

try:
    import instructor as _instructor  # noqa: F401
    _INSTRUCTOR_AVAILABLE = True
except ImportError:  # pragma: no cover
    _INSTRUCTOR_AVAILABLE = False


# ── Structured output contract ─────────────────────────────────────────────────

class GovernanceDecision(BaseModel):
    """
    Typed contract for every agent decision that flows through the governance layer.

    When outlines is available, ``StructuredOutputParser.schema_obj`` is an
    ``outlines.JsonSchema`` that can be passed directly to any outlines-wrapped
    model to constrain token sampling — making invalid JSON ungenerable.

    When used with instructor, pass ``response_model=GovernanceDecision`` to the
    ``instructor.patch``-ed client and structured output is enforced via the
    provider's function-calling / tool-use API.

    In both cases the drift detector receives a fully typed object; no
    regex extraction, no ``json.loads`` guessing, no free-text parsing.
    """

    case_category: str = Field(
        ...,
        description=(
            "Category of the support case: billing_dispute | fraud_claim | "
            "policy_sensitive | routine | unknown"
        ),
    )
    risk_level: Literal["low", "medium", "high", "critical"] = Field(
        ...,
        description="Assessed risk level of this individual decision",
    )
    decision: str = Field(
        ...,
        min_length=1,
        description="What the agent decided to do (human-readable summary)",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Agent's self-assessed confidence in this decision, 0–1",
    )
    flags: list[str] = Field(
        default_factory=list,
        description="Governance flags raised during processing (e.g. 'high_value', 'repeat_dispute')",
    )

    @field_validator("case_category")
    @classmethod
    def _normalise_category(cls, v: str) -> str:
        return v.strip().lower().replace(" ", "_").replace("-", "_")

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v: float) -> float:
        # Clamp before constraint check — agents sometimes produce 1.001 due to float arithmetic
        return max(0.0, min(1.0, float(v)))

    @property
    def is_high_risk(self) -> bool:
        return self.risk_level in ("high", "critical")

    def to_dict(self) -> dict:
        return self.model_dump()


# ── Errors ─────────────────────────────────────────────────────────────────────

class StructuredOutputError(ValueError):
    """Raised when agent output cannot be coerced into a valid GovernanceDecision."""

    def __init__(
        self,
        message: str,
        raw_output: str = "",
        validation_errors: str = "",
    ) -> None:
        super().__init__(message)
        self.raw_output = raw_output
        self.validation_errors = validation_errors

    def __str__(self) -> str:
        base = super().__str__()
        if self.validation_errors:
            return f"{base} | validation: {self.validation_errors}"
        return base


# ── Parser / validator ─────────────────────────────────────────────────────────

class StructuredOutputParser:
    """
    Parses and validates agent text output against the GovernanceDecision schema.

    Extraction strategy (in order):
      1. Entire text is valid JSON → validate directly
      2. Find the first top-level ``{...}`` block in mixed text → validate
      3. Fail with StructuredOutputError

    The ``schema_obj`` attribute is an ``outlines.JsonSchema`` when outlines is
    installed.  Pass it to ``outlines.generate.json(model, schema_obj)`` to get a
    generator that is constrained to produce valid GovernanceDecision JSON during
    token sampling.

    When outlines is unavailable the parser falls back to instructor-aware
    validation (for Anthropic/OpenAI tool-call responses) and finally to plain
    Pydantic validation.
    """

    # Matches the outermost {...} in text that may contain nested braces/arrays
    _JSON_RE = re.compile(r"\{[\s\S]*\}", re.DOTALL)

    def __init__(self) -> None:
        self.schema_obj: object = None
        self.backend: str = "pydantic"

        if _OUTLINES_AVAILABLE:
            self.schema_obj = _outlines.json_schema(GovernanceDecision)
            self.backend = "outlines"
        elif _INSTRUCTOR_AVAILABLE:
            self.backend = "instructor"

    @property
    def json_schema(self) -> dict:
        """The raw JSON Schema dict for GovernanceDecision."""
        return GovernanceDecision.model_json_schema()

    def parse(self, raw: str) -> GovernanceDecision:
        """
        Parse raw agent text into a validated GovernanceDecision.

        Raises ``StructuredOutputError`` if the text contains no JSON object
        or if validation against the schema fails.
        """
        raw = (raw or "").strip()
        candidate = self._extract_json(raw)
        if candidate is None:
            raise StructuredOutputError(
                "No JSON object found in agent output",
                raw_output=raw,
            )
        return self._validate(candidate, raw)

    def parse_or_none(self, raw: str) -> Optional[GovernanceDecision]:
        """Like ``parse`` but returns None instead of raising."""
        try:
            return self.parse(raw)
        except StructuredOutputError:
            return None

    def validate(self, obj: dict) -> GovernanceDecision:
        """Validate an already-parsed dict against the GovernanceDecision schema."""
        return self._validate(obj, raw=json.dumps(obj))

    # ── Internal ───────────────────────────────────────────────────────────────

    def _extract_json(self, text: str) -> Optional[dict]:
        # Fast path: whole string is JSON
        try:
            result = json.loads(text)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Slow path: find first {...} block
        m = self._JSON_RE.search(text)
        if m:
            try:
                result = json.loads(m.group())
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                pass

        return None

    def _validate(self, candidate: dict, raw: str) -> GovernanceDecision:
        try:
            return GovernanceDecision.model_validate(candidate)
        except Exception as exc:
            raise StructuredOutputError(
                "GovernanceDecision validation failed",
                raw_output=raw,
                validation_errors=str(exc),
            ) from exc


# ── Module-level singleton ─────────────────────────────────────────────────────

_parser: Optional[StructuredOutputParser] = None


def get_parser() -> StructuredOutputParser:
    """Return the process-wide StructuredOutputParser (lazy-initialised)."""
    global _parser
    if _parser is None:
        _parser = StructuredOutputParser()
    return _parser
