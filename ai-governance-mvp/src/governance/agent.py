"""
GovernanceAgent: LLM wrapper with enforced structured output.

This is the production integration point for Req 7 (Constrained Decoding).
Every agent decision flows through one of three backends, selected at
construction time based on what's installed:

  Tier 1 — outlines (best):
    Model token sampling is constrained by an FSM derived from the
    GovernanceDecision JSON schema.  Malformed output is structurally
    impossible.  Use with any HuggingFace or vLLM model.

    Generator is built once from schema_obj and reused across calls:
      generator = outlines.generate.json(model, schema_obj)
      gd: GovernanceDecision = generator(prompt)

  Tier 2 — instructor (good):
    The LLM client is patched with instructor; the model is asked to call
    a function matching the GovernanceDecision schema.  Structured output
    is enforced by the provider's function-calling / tool-use API.

    Example (OpenAI):
      client = instructor.from_openai(openai.OpenAI())
      gd = client.chat.completions.create(
          model="gpt-4o", response_model=GovernanceDecision, ...
      )

  Tier 3 — parser fallback (safe):
    The raw LLM response is parsed post-hoc by StructuredOutputParser.
    May raise StructuredOutputError if the model produces no JSON, but
    never returns an invalid GovernanceDecision — the parser validates
    every field before returning.

All three tiers return a GovernanceDecision; the caller never sees raw text.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Callable, Optional

from ..governance.config import GovernanceConfig
from ..governance.schema import AgentDecision
from ..governance.structured import (
    GovernanceDecision,
    StructuredOutputError,
    StructuredOutputParser,
    _INSTRUCTOR_AVAILABLE,
    _OUTLINES_AVAILABLE,
    get_parser,
)
from ..ingestion.ingestor import DecisionIngestor
from ..ingestion.store import DecisionStore

# ── Default prompt template ────────────────────────────────────────────────────

_DEFAULT_PROMPT = """\
You are a support agent governance system. Analyze the following support case
and produce a structured governance decision.

Case text:
{case_text}

Respond ONLY with a JSON object matching this schema:
  case_category: billing_dispute | fraud_claim | policy_sensitive | routine | unknown
  risk_level: low | medium | high | critical
  decision: what the agent decided to do (one sentence)
  confidence: float 0.0–1.0
  flags: list of governance flags raised (e.g. ["high_value", "repeat_dispute"])
"""

# ── Backend tier selection ─────────────────────────────────────────────────────

_TIER_OUTLINES = "outlines"
_TIER_INSTRUCTOR = "instructor"
_TIER_PARSER = "parser"


class GovernanceAgent:
    """
    LLM wrapper that guarantees every call returns a valid GovernanceDecision.

    ``generate_fn`` is the only dependency on the model provider.  It should
    accept a prompt string and return the model's raw text response::

        agent = GovernanceAgent(
            generate_fn=lambda prompt: my_llm.generate(prompt),
            config=GovernanceConfig.default(),
        )
        decision = agent.decide(case_text="Customer was billed twice.", case_id="CASE-1")

    For outlines tier, pass an ``outlines_model`` instead of a ``generate_fn``::

        import outlines
        model = outlines.models.transformers("mistralai/Mistral-7B-v0.1")
        agent = GovernanceAgent.from_outlines(model, config=GovernanceConfig.default())

    For instructor tier, pass an already-patched instructor client::

        import instructor, openai
        client = instructor.from_openai(openai.OpenAI())
        agent = GovernanceAgent.from_instructor(client, model="gpt-4o", config=...)
    """

    def __init__(
        self,
        generate_fn: Callable[[str], str],
        config: GovernanceConfig,
        ingestor: Optional[DecisionIngestor] = None,
        prompt_template: str = _DEFAULT_PROMPT,
        tier: str = _TIER_PARSER,
    ) -> None:
        self._generate_fn = generate_fn
        self._config = config
        self._ingestor = ingestor
        self._prompt_template = prompt_template
        self._tier = tier
        self._parser: StructuredOutputParser = get_parser()
        self._call_count: int = 0
        self._error_count: int = 0

    # ── Factory methods ────────────────────────────────────────────────────────

    @classmethod
    def from_outlines(
        cls,
        outlines_model: Any,
        config: GovernanceConfig,
        ingestor: Optional[DecisionIngestor] = None,
        prompt_template: str = _DEFAULT_PROMPT,
    ) -> "GovernanceAgent":
        """
        Build a GovernanceAgent backed by outlines constrained generation.

        ``outlines_model`` should be any model wrapped with outlines
        (e.g. from ``outlines.models.transformers(...)``).

        The generator function is built once using the GovernanceDecision
        JSON schema and reused for all subsequent calls.
        """
        if not _OUTLINES_AVAILABLE:
            raise ImportError(
                "outlines is required for GovernanceAgent.from_outlines(). "
                "Install it with: pip install outlines"
            )
        import json as _json
        import outlines as _outlines

        schema_obj = get_parser().schema_obj

        # outlines v0.x: outlines.generate.json(model, schema)
        # outlines v1.x: outlines.generator(model, output_type=schema)
        if hasattr(_outlines, "generate"):
            generator = _outlines.generate.json(outlines_model, schema_obj)
        else:
            generator = _outlines.generator(outlines_model, output_type=schema_obj)

        def _generate(prompt: str) -> str:
            result = generator(prompt)
            # outlines may return a Pydantic model, dict, or string
            if isinstance(result, dict):
                return _json.dumps(result)
            if hasattr(result, "model_dump_json"):
                return result.model_dump_json()
            return str(result)

        return cls(
            generate_fn=_generate,
            config=config,
            ingestor=ingestor,
            prompt_template=prompt_template,
            tier=_TIER_OUTLINES,
        )

    @classmethod
    def from_instructor(
        cls,
        instructor_client: Any,
        model: str,
        config: GovernanceConfig,
        ingestor: Optional[DecisionIngestor] = None,
        prompt_template: str = _DEFAULT_PROMPT,
    ) -> "GovernanceAgent":
        """
        Build a GovernanceAgent backed by instructor structured output.

        ``instructor_client`` should be a client patched with instructor
        (e.g. ``instructor.from_openai(openai.OpenAI())`` or
        ``instructor.from_anthropic(anthropic.Anthropic())``).
        """
        if not _INSTRUCTOR_AVAILABLE:
            raise ImportError(
                "instructor is required for GovernanceAgent.from_instructor(). "
                "Install it with: pip install instructor"
            )

        def _generate(prompt: str) -> str:
            gd = instructor_client.chat.completions.create(
                model=model,
                response_model=GovernanceDecision,
                messages=[{"role": "user", "content": prompt}],
            )
            return gd.model_dump_json()

        return cls(
            generate_fn=_generate,
            config=config,
            ingestor=ingestor,
            prompt_template=prompt_template,
            tier=_TIER_INSTRUCTOR,
        )

    # ── Core interface ─────────────────────────────────────────────────────────

    def decide(
        self,
        case_text: str,
        case_id: str = "",
        extra_context: Optional[dict] = None,
    ) -> GovernanceDecision:
        """
        Produce a governance decision for a support case.

        Calls the underlying LLM, enforces the GovernanceDecision schema,
        and returns a fully validated typed object.  Never returns raw text.

        Raises StructuredOutputError if the model produces output that cannot
        be coerced into a valid GovernanceDecision (only possible in parser tier).
        """
        prompt = self._build_prompt(case_text, extra_context)
        self._call_count += 1
        try:
            raw = self._generate_fn(prompt)
            gd = self._parser.parse(raw)
            return gd
        except StructuredOutputError:
            self._error_count += 1
            raise

    def decide_and_ingest(
        self,
        case_text: str,
        case_id: str,
        agent_version: str = "unknown",
        processing_time_ms: float = 500.0,
    ) -> AgentDecision:
        """
        Produce a governance decision and immediately store it for drift tracking.

        Requires an ingestor to be configured (pass via constructor or
        ``with_ingestor()``).
        """
        if self._ingestor is None:
            raise RuntimeError(
                "GovernanceAgent.decide_and_ingest() requires an ingestor. "
                "Pass ingestor= to the constructor or call with_ingestor()."
            )
        start = time.perf_counter()
        gd = self.decide(case_text=case_text, case_id=case_id)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return self._ingestor.ingest_governance_decision(
            gd,
            case_id=case_id,
            agent_version=agent_version,
            processing_time_ms=elapsed_ms,
            timestamp=datetime.utcnow(),
        )

    def with_ingestor(self, ingestor: DecisionIngestor) -> "GovernanceAgent":
        """Return a new agent with an ingestor attached (non-mutating)."""
        return GovernanceAgent(
            generate_fn=self._generate_fn,
            config=self._config,
            ingestor=ingestor,
            prompt_template=self._prompt_template,
            tier=self._tier,
        )

    # ── Stats ──────────────────────────────────────────────────────────────────

    @property
    def call_count(self) -> int:
        return self._call_count

    @property
    def error_count(self) -> int:
        return self._error_count

    @property
    def tier(self) -> str:
        return self._tier

    @property
    def error_rate(self) -> float:
        if self._call_count == 0:
            return 0.0
        return self._error_count / self._call_count

    # ── Internal ───────────────────────────────────────────────────────────────

    def _build_prompt(self, case_text: str, extra: Optional[dict]) -> str:
        ctx = {"case_text": case_text}
        if extra:
            ctx.update(extra)
        try:
            return self._prompt_template.format(**ctx)
        except KeyError:
            return f"{self._prompt_template}\n\nCase: {case_text}"


# ── Convenience factory ────────────────────────────────────────────────────────

def make_agent(
    generate_fn: Callable[[str], str],
    config: Optional[GovernanceConfig] = None,
    store: Optional[DecisionStore] = None,
) -> GovernanceAgent:
    """
    Quickstart factory: build a parser-tier GovernanceAgent with optional auto-ingestor.

    ``generate_fn`` is any callable that takes a prompt string and returns the
    model's raw text response.  Pair with any LLM API::

        import anthropic
        client = anthropic.Anthropic()

        def generate(prompt: str) -> str:
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text

        agent = make_agent(generate, config=GovernanceConfig.default(), store=store)
        decision = agent.decide("Customer disputes $150 charge from last month.")
    """
    from ..governance.config import GovernanceConfig as _GC
    cfg = config or _GC.default()
    ingestor = None
    if store is not None:
        ingestor = DecisionIngestor(store, cfg)
    return GovernanceAgent(generate_fn=generate_fn, config=cfg, ingestor=ingestor)
