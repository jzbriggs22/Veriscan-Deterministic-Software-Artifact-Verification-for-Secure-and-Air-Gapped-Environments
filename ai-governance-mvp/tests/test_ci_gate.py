"""Tests for ci_gate.py — governance CI/CD gate script.

Tests the main() function directly to avoid subprocess overhead, covering:
- Exit codes: 0 (SAFE), 1 (BLOCKED or --fail-on-warning), 2 (WARNING), 3 (usage error)
- JSON output to stdout
- --output flag writing to file
- --fail-on-warning flag
- Invalid file path / malformed JSON edge cases
- Env var threshold overrides
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# ci_gate.py lives at repo root; ensure it's importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ci_gate import main


# ── Decision factories ─────────────────────────────────────────────────────────

def _routine_decision(n: int = 1) -> list[dict]:
    return [
        {
            "case_category": "routine",
            "risk_level": "low",
            "decision": f"Resolved case {i}.",
            "confidence": 0.90,
            "flags": [],
        }
        for i in range(n)
    ]


def _billing_high_risk(n: int = 1) -> list[dict]:
    return [
        {
            "case_category": "billing_dispute",
            "risk_level": "high",
            "decision": f"Escalated billing case {i}.",
            "confidence": 0.85,
            "flags": ["high_value"],
        }
        for i in range(n)
    ]


def _error_heavy(n: int = 20) -> list[dict]:
    """Decisions with very high error rate to trigger BLOCKED."""
    decisions = []
    for i in range(n):
        decisions.append({
            "case_category": "billing_dispute",
            "risk_level": "low" if i % 2 == 0 else "high",
            "decision": "Error processing case.",
            "confidence": 0.20,
            "flags": ["error"],
            "_outcome": "error",
        })
    return decisions


def _write_decisions(tmp_path: Path, decisions: list[dict], filename: str = "decisions.json") -> str:
    p = tmp_path / filename
    p.write_text(json.dumps(decisions))
    return str(p)


# ── Exit code 0 — SAFE_TO_DEPLOY ──────────────────────────────────────────────

class TestSafeCase:
    def test_returns_zero_for_valid_decisions(self, tmp_path, capsys):
        path = _write_decisions(tmp_path, _routine_decision(10))
        rc = main(["--decisions", path, "--agent-version", "v1.0", "--quiet"])
        assert rc == 0

    def test_stdout_is_valid_json(self, tmp_path, capsys):
        path = _write_decisions(tmp_path, _routine_decision(5))
        main(["--decisions", path, "--quiet"])
        captured = capsys.readouterr().out
        data = json.loads(captured)
        assert "recommendation" in data

    def test_json_contains_agent_version(self, tmp_path, capsys):
        path = _write_decisions(tmp_path, _routine_decision(5))
        main(["--decisions", path, "--agent-version", "release-2.0", "--quiet"])
        data = json.loads(capsys.readouterr().out)
        assert data["agent_version"] == "release-2.0"

    def test_total_submitted_matches(self, tmp_path, capsys):
        decisions = _routine_decision(7)
        path = _write_decisions(tmp_path, decisions)
        main(["--decisions", path, "--quiet"])
        data = json.loads(capsys.readouterr().out)
        assert data["total_submitted"] == 7


# ── Exit code 3 — usage / config errors ───────────────────────────────────────

class TestUsageErrors:
    def test_missing_file_exits_3(self, tmp_path):
        rc = main(["--decisions", str(tmp_path / "nonexistent.json"), "--quiet"])
        assert rc == 3

    def test_malformed_json_exits_3(self, tmp_path, capsys):
        p = tmp_path / "bad.json"
        p.write_text("this is not json {{{")
        rc = main(["--decisions", str(p), "--quiet"])
        assert rc == 3

    def test_non_array_json_exits_3(self, tmp_path):
        p = tmp_path / "obj.json"
        p.write_text('{"key": "value"}')
        rc = main(["--decisions", str(p), "--quiet"])
        assert rc == 3


# ── --output flag ─────────────────────────────────────────────────────────────

class TestOutputFlag:
    def test_output_file_written(self, tmp_path, capsys):
        decisions_path = _write_decisions(tmp_path, _routine_decision(5))
        out_path = tmp_path / "report.json"
        main(["--decisions", decisions_path, "--output", str(out_path), "--quiet"])
        assert out_path.exists()

    def test_output_file_is_valid_json(self, tmp_path, capsys):
        decisions_path = _write_decisions(tmp_path, _routine_decision(5))
        out_path = tmp_path / "report.json"
        main(["--decisions", decisions_path, "--output", str(out_path), "--quiet"])
        data = json.loads(out_path.read_text())
        assert "recommendation" in data

    def test_output_file_matches_stdout(self, tmp_path, capsys):
        decisions_path = _write_decisions(tmp_path, _routine_decision(5))
        out_path = tmp_path / "report.json"
        main(["--decisions", decisions_path, "--output", str(out_path), "--quiet"])
        stdout_data = json.loads(capsys.readouterr().out)
        file_data = json.loads(out_path.read_text())
        assert stdout_data["recommendation"] == file_data["recommendation"]
        assert stdout_data["total_submitted"] == file_data["total_submitted"]


# ── --quiet flag ───────────────────────────────────────────────────────────────

class TestQuietFlag:
    def test_quiet_suppresses_non_json_lines(self, tmp_path, capsys):
        path = _write_decisions(tmp_path, _routine_decision(5))
        main(["--decisions", path, "--quiet"])
        out = capsys.readouterr().out.strip()
        # With --quiet, stdout should only be JSON (no [ci_gate] lines)
        data = json.loads(out)
        assert isinstance(data, dict)

    def test_without_quiet_prints_labels(self, tmp_path, capsys):
        path = _write_decisions(tmp_path, _routine_decision(5))
        main(["--decisions", path])
        out = capsys.readouterr().out
        assert "[ci_gate]" in out


# ── JSON report structure ──────────────────────────────────────────────────────

class TestReportStructure:
    def test_all_required_fields_present(self, tmp_path, capsys):
        path = _write_decisions(tmp_path, _routing_mix())
        main(["--decisions", path, "--quiet"])
        data = json.loads(capsys.readouterr().out)
        required = {
            "passed", "recommendation", "agent_version", "generated_at",
            "total_submitted", "valid_decisions", "schema_error_count",
            "summary", "threshold_violations", "high_risk_failures",
            "category_results",
        }
        assert required.issubset(data.keys())

    def test_category_results_is_list(self, tmp_path, capsys):
        path = _write_decisions(tmp_path, _routing_mix())
        main(["--decisions", path, "--quiet"])
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data["category_results"], list)

    def test_generated_at_is_iso8601(self, tmp_path, capsys):
        path = _write_decisions(tmp_path, _routine_decision(3))
        main(["--decisions", path, "--quiet"])
        data = json.loads(capsys.readouterr().out)
        from datetime import datetime
        dt = datetime.fromisoformat(data["generated_at"])
        assert isinstance(dt, datetime)

    def test_schema_errors_reported_for_bad_input(self, tmp_path, capsys):
        bad = [{"garbage": "data", "not_a_decision": True}]
        path = _write_decisions(tmp_path, bad)
        main(["--decisions", path, "--quiet"])
        data = json.loads(capsys.readouterr().out)
        assert data["schema_error_count"] >= 1


# ── --fail-on-warning flag ────────────────────────────────────────────────────

class TestFailOnWarning:
    def test_warning_exits_2_without_flag(self, tmp_path, capsys, monkeypatch):
        """Patch validator to return WARNING to test flag behavior."""
        from unittest.mock import MagicMock, patch
        from src.governance.preflight import PreflightReport
        from datetime import datetime

        mock_report = PreflightReport(
            passed=True,
            agent_version="v1.0",
            generated_at=datetime.utcnow(),
            total_submitted=5,
            valid_decisions=5,
            schema_error_count=0,
            category_results=[],
            threshold_violations=[],
            high_risk_failures=[],
            recommendation="WARNING",
            summary="Advisory issues present",
        )

        path = _write_decisions(tmp_path, _routine_decision(5))
        with patch("ci_gate.PreflightValidator") as MockValidator:
            MockValidator.return_value.validate_batch.return_value = mock_report
            rc = main(["--decisions", path, "--quiet"])
        assert rc == 2

    def test_warning_exits_1_with_fail_on_warning(self, tmp_path, capsys):
        from unittest.mock import patch
        from src.governance.preflight import PreflightReport
        from datetime import datetime

        mock_report = PreflightReport(
            passed=True,
            agent_version="v1.0",
            generated_at=datetime.utcnow(),
            total_submitted=5,
            valid_decisions=5,
            schema_error_count=0,
            category_results=[],
            threshold_violations=[],
            high_risk_failures=[],
            recommendation="WARNING",
            summary="Advisory issues present",
        )

        path = _write_decisions(tmp_path, _routine_decision(5))
        with patch("ci_gate.PreflightValidator") as MockValidator:
            MockValidator.return_value.validate_batch.return_value = mock_report
            rc = main(["--decisions", path, "--quiet", "--fail-on-warning"])
        assert rc == 1

    def test_blocked_always_exits_1(self, tmp_path, capsys):
        from unittest.mock import patch
        from src.governance.preflight import PreflightReport
        from datetime import datetime

        mock_report = PreflightReport(
            passed=False,
            agent_version="v1.0",
            generated_at=datetime.utcnow(),
            total_submitted=5,
            valid_decisions=5,
            schema_error_count=0,
            category_results=[],
            threshold_violations=["Error rate too high"],
            high_risk_failures=[],
            recommendation="BLOCKED",
            summary="Deployment blocked",
        )

        path = _write_decisions(tmp_path, _routine_decision(5))
        with patch("ci_gate.PreflightValidator") as MockValidator:
            MockValidator.return_value.validate_batch.return_value = mock_report
            rc = main(["--decisions", path, "--quiet"])
        assert rc == 1


# ── Env var config overrides ───────────────────────────────────────────────────

class TestEnvVarOverrides:
    def test_invalid_min_detection_size_exits_3(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GOVERNANCE_DETECTION_WINDOW", "not_a_number")
        path = _write_decisions(tmp_path, _routine_decision(5))
        rc = main(["--decisions", path, "--quiet"])
        assert rc == 3

    def test_invalid_error_rate_threshold_exits_3(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GOVERNANCE_MAX_ERROR_RATE", "not_a_float")
        path = _write_decisions(tmp_path, _routine_decision(5))
        rc = main(["--decisions", path, "--quiet"])
        assert rc == 3

    def test_valid_env_vars_accepted(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("GOVERNANCE_DETECTION_WINDOW", "5")
        monkeypatch.setenv("GOVERNANCE_MAX_ERROR_RATE", "0.3")
        path = _write_decisions(tmp_path, _routine_decision(10))
        rc = main(["--decisions", path, "--quiet"])
        assert rc in (0, 1, 2)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _routing_mix() -> list[dict]:
    return _routine_decision(5) + _billing_high_risk(5)
