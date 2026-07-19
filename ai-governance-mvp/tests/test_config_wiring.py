"""
Regression tests for configuration-wiring fixes:

  1. config/governance.yaml declares the time_window section the loader
     actually reads, so the operative detection windows are tunable from
     the file (previously only the inert count-based keys were present).
  2. ci_gate.py accepts --config to load a governance YAML instead of
     silently using built-in defaults.
  3. ci_gate.py env-var overrides apply to high-risk category thresholds,
     not just the defaults that thresholds_for() shadows.
  4. serve.py wires the SSE event broker into the scheduler so the
     documented /governance/events/stream events actually fire.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from ci_gate import _build_config, main
from src.governance.config import GovernanceConfig
from src.governance.schema import CaseCategory


GOVERNANCE_YAML = REPO_ROOT / "config" / "governance.yaml"


# ── governance.yaml declares the operative windows ────────────────────────────

class TestGovernanceYamlTimeWindows:
    def test_shipped_yaml_has_explicit_time_window_section(self):
        import yaml

        data = yaml.safe_load(GOVERNANCE_YAML.read_text())
        assert "time_window" in data, (
            "governance.yaml must declare the time_window section the loader "
            "reads — without it the file's documented knobs are inert"
        )
        tw = data["time_window"]
        assert set(tw) == {
            "use_time_windows",
            "baseline_lookback_days",
            "baseline_exclusion_hours",
            "detection_hours",
        }

    def test_loader_roundtrips_shipped_time_window_values(self):
        cfg = GovernanceConfig.from_yaml(GOVERNANCE_YAML)
        assert cfg.time_window.use_time_windows is True
        assert cfg.time_window.baseline_lookback_days == 30
        assert cfg.time_window.baseline_exclusion_hours == 168
        assert cfg.time_window.detection_hours == 24

    def test_time_window_values_are_tunable_from_yaml(self, tmp_path):
        custom = tmp_path / "custom.yaml"
        custom.write_text(
            "time_window:\n"
            "  use_time_windows: false\n"
            "  baseline_lookback_days: 14\n"
            "  detection_hours: 6\n"
        )
        cfg = GovernanceConfig.from_yaml(custom)
        assert cfg.time_window.use_time_windows is False
        assert cfg.time_window.baseline_lookback_days == 14
        assert cfg.time_window.detection_hours == 6


# ── ci_gate --config ──────────────────────────────────────────────────────────

def _write_decisions(tmp_path: Path, n: int = 5) -> str:
    decisions = [
        {
            "case_category": "routine",
            "risk_level": "low",
            "decision": "Resolved the request.",
            "confidence": 0.9,
            "flags": [],
        }
        for _ in range(n)
    ]
    p = tmp_path / "decisions.json"
    p.write_text(json.dumps(decisions))
    return str(p)


class TestCiGateConfigFlag:
    def test_build_config_loads_yaml(self):
        cfg = _build_config(str(GOVERNANCE_YAML))
        # Values only present in the shipped YAML's high-risk section prove
        # the file was actually read rather than defaults being used.
        fraud = cfg.thresholds_for(CaseCategory.FRAUD_CLAIM)
        assert fraud.critical_score == 0.60
        assert fraud.max_error_rate == 0.10

    def test_missing_config_file_exits_3(self, tmp_path):
        decisions = _write_decisions(tmp_path)
        rc = main([
            "--decisions", decisions,
            "--config", str(tmp_path / "nope.yaml"),
            "--quiet",
        ])
        assert rc == 3

    def test_gate_runs_with_shipped_config(self, tmp_path, capsys):
        decisions = _write_decisions(tmp_path)
        rc = main([
            "--decisions", decisions,
            "--config", str(GOVERNANCE_YAML),
            "--agent-version", "v-cfg",
            "--quiet",
        ])
        assert rc in (0, 1, 2)
        out = capsys.readouterr().out
        report = json.loads(out)
        assert report["agent_version"] == "v-cfg"

    def test_omitting_config_still_uses_defaults(self, tmp_path):
        cfg = _build_config(None)
        default = GovernanceConfig.default()
        assert (
            cfg.default_thresholds.max_error_rate
            == default.default_thresholds.max_error_rate
        )


# ── ci_gate env overrides reach high-risk categories ──────────────────────────

class TestCiGateEnvOverridesHighRisk:
    def _with_env(self, key: str, value: str):
        old = os.environ.get(key)
        os.environ[key] = value

        def restore():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old

        return restore

    def test_max_error_rate_override_applies_to_every_category(self):
        restore = self._with_env("GOVERNANCE_MAX_ERROR_RATE", "0.03")
        try:
            cfg = _build_config(None)
            for category in (
                CaseCategory.ROUTINE,
                CaseCategory.BILLING_DISPUTE,
                CaseCategory.FRAUD_CLAIM,
                CaseCategory.POLICY_SENSITIVE,
            ):
                assert cfg.thresholds_for(category).max_error_rate == 0.03, (
                    f"{category.value} must honor the env override"
                )
        finally:
            restore()

    def test_detection_window_override_applies_to_every_category(self):
        restore = self._with_env("GOVERNANCE_DETECTION_WINDOW", "42")
        try:
            cfg = _build_config(None)
            for category in (
                CaseCategory.ROUTINE,
                CaseCategory.FRAUD_CLAIM,
            ):
                assert cfg.thresholds_for(category).min_detection_size == 42
        finally:
            restore()

    def test_env_override_composes_with_yaml_config(self):
        restore = self._with_env("GOVERNANCE_MAX_ERROR_RATE", "0.05")
        try:
            cfg = _build_config(str(GOVERNANCE_YAML))
            # YAML-specific value survives where not overridden...
            assert cfg.thresholds_for(CaseCategory.FRAUD_CLAIM).critical_score == 0.60
            # ...and the override wins on the field it targets.
            assert cfg.thresholds_for(CaseCategory.FRAUD_CLAIM).max_error_rate == 0.05
        finally:
            restore()

    def test_invalid_env_value_exits_3(self, tmp_path):
        restore = self._with_env("GOVERNANCE_MAX_ERROR_RATE", "not-a-float")
        try:
            decisions = _write_decisions(tmp_path)
            rc = main(["--decisions", decisions, "--quiet"])
            assert rc == 3
        finally:
            restore()


# ── serve.py wires the SSE broker ─────────────────────────────────────────────

class TestServeWiresEventBroker:
    def test_serve_source_passes_event_broker_to_scheduler(self):
        # serve.py is an entrypoint script (argparse + uvicorn.run), so assert
        # on its source rather than executing it: the DetectionScheduler call
        # must wire the same broker singleton the SSE endpoint reads.
        source = (REPO_ROOT / "serve.py").read_text()
        assert "event_broker=get_broker()" in source
        assert "from src.engine.events import get_broker" in source

    def test_scheduler_publishes_to_broker_when_wired(self):
        # End-to-end for the wiring serve.py now uses: a scheduler constructed
        # with the broker publishes at least the cycle_complete event, which
        # bumps the broker's published_total counter.
        from src.detection.detector import DriftDetector
        from src.engine.alerts import AlertEngine
        from src.engine.events import GovernanceEventBroker
        from src.engine.rollback import RollbackEngine
        from src.engine.scheduler import DetectionScheduler
        from src.ingestion.store import DecisionStore

        config = GovernanceConfig.default()
        store = DecisionStore()
        broker = GovernanceEventBroker()

        scheduler = DetectionScheduler(
            store=store,
            detector=DriftDetector(store, config),
            alert_engine=AlertEngine(store, config),
            rollback_engine=RollbackEngine(store, config),
            event_broker=broker,
        )
        assert broker.published_total == 0
        scheduler.run_now()
        assert broker.published_total >= 1, (
            "a wired scheduler must publish cycle_complete on every cycle"
        )
