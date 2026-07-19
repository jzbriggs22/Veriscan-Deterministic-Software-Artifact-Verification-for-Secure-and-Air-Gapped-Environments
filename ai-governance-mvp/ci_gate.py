#!/usr/bin/env python3
"""
ci_gate.py — Governance pre-deployment CI/CD gate.

Submits a batch of agent decision JSONs to the PreflightValidator and exits
with a machine-readable result.

Exit codes:
  0 — SAFE_TO_DEPLOY  (all checks passed)
  1 — BLOCKED         (governance thresholds violated; deployment should stop)
  2 — WARNING         (advisory issues; deployment continues but is flagged)
  3 — Usage / config error

Usage:
  python ci_gate.py --decisions decisions.json [options]

  decisions.json must be a JSON array of governance decision objects, e.g.:
    [
      {"case_category": "billing_dispute", "risk_level": "high",
       "decision": "Refund approved.", "confidence": 0.91, "flags": []},
      ...
    ]

Options:
  --decisions FILE       Path to JSON file with decision array (required)
  --config FILE          Governance YAML config (e.g. config/governance.yaml);
                         omitted → built-in defaults
  --agent-version VER    Version string for this deployment (default: "unknown")
  --output FILE          Write JSON report to FILE in addition to stdout
  --quiet                Suppress non-JSON output (still writes JSON to stdout)
  --fail-on-warning      Exit 1 on WARNING as well as BLOCKED

Environment variables (override the loaded config, applied to the default
thresholds AND every high-risk category):
  GOVERNANCE_DETECTION_WINDOW     Minimum decisions needed per category (int)
  GOVERNANCE_MAX_ERROR_RATE       Max tolerated error rate (float, 0–1)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.governance.config import GovernanceConfig
from src.governance.preflight import PreflightValidator


# ── Internal exception used to carry exit codes through the call stack ─────────

class _GateError(Exception):
    def __init__(self, msg: str, exit_code: int = 3) -> None:
        super().__init__(msg)
        self.exit_code = exit_code


def _die(msg: str, exit_code: int = 3) -> None:
    raise _GateError(msg, exit_code)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _load_decisions(path: str) -> list[dict]:
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        _die(f"Decisions file not found: {path!r}", exit_code=3)
    except OSError as e:
        _die(f"Cannot read {path!r}: {e}", exit_code=3)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        _die(f"Invalid JSON in {path!r}: {e}", exit_code=3)

    if not isinstance(data, list):
        _die(f"{path!r} must contain a JSON array, got {type(data).__name__}", exit_code=3)

    return data


def _build_config(config_path: Optional[str] = None) -> GovernanceConfig:
    """Build config (from YAML if given) with optional env var overrides.

    Env overrides apply to the default thresholds and to every high-risk
    category's thresholds — thresholds_for() resolves high-risk categories
    to their own DriftThresholds objects, so mutating only the defaults
    would leave exactly the categories the gate polices unaffected.
    """
    if config_path is not None:
        try:
            cfg = GovernanceConfig.from_yaml(config_path)
        except FileNotFoundError:
            _die(f"Config file not found: {config_path!r}", exit_code=3)
        except (ValueError, KeyError) as e:
            _die(f"Invalid config file {config_path!r}: {e}", exit_code=3)
    else:
        cfg = GovernanceConfig.default()

    all_thresholds = [cfg.default_thresholds] + [
        hrc.thresholds for hrc in cfg.high_risk_categories
    ]

    env_window = os.environ.get("GOVERNANCE_DETECTION_WINDOW")
    env_err = os.environ.get("GOVERNANCE_MAX_ERROR_RATE")

    if env_window is not None:
        try:
            window = int(env_window)
        except (ValueError, TypeError) as e:
            _die(f"Invalid GOVERNANCE_DETECTION_WINDOW: {e}", exit_code=3)
        for thresholds in all_thresholds:
            thresholds.min_detection_size = window

    if env_err is not None:
        try:
            err_rate = float(env_err)
        except (ValueError, TypeError) as e:
            _die(f"Invalid GOVERNANCE_MAX_ERROR_RATE: {e}", exit_code=3)
        for thresholds in all_thresholds:
            thresholds.max_error_rate = err_rate

    return cfg


def _report_to_dict(report) -> dict:
    return {
        "passed": report.passed,
        "recommendation": report.recommendation,
        "agent_version": report.agent_version,
        "generated_at": report.generated_at.isoformat(),
        "total_submitted": report.total_submitted,
        "valid_decisions": report.valid_decisions,
        "schema_error_count": report.schema_error_count,
        "summary": report.summary,
        "threshold_violations": report.threshold_violations,
        "high_risk_failures": report.high_risk_failures,
        "category_results": [
            {
                "category": r.category,
                "total": r.total,
                "valid_schema": r.valid_schema,
                "high_risk_correct": r.high_risk_correct,
                "error_rate": r.error_rate,
                "resolution_rate": r.resolution_rate,
                "escalation_rate": r.escalation_rate,
                "rejection_rate": r.rejection_rate,
                "mean_confidence": r.mean_confidence,
                "schema_errors": r.schema_errors,
                "issues": r.threshold_violations,
                "passed": r.passed,
            }
            for r in report.category_results
        ],
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Governance CI gate — validates agent decisions before deployment.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--decisions", required=True, metavar="FILE",
        help="JSON file containing array of governance decision objects",
    )
    parser.add_argument(
        "--config", metavar="FILE",
        help="Governance YAML config (e.g. config/governance.yaml); "
             "omitted → built-in defaults",
    )
    parser.add_argument(
        "--agent-version", default="unknown", metavar="VER",
        help="Version string for this deployment (default: unknown)",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Write JSON report to FILE",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress non-JSON output (still writes JSON to stdout)",
    )
    parser.add_argument(
        "--fail-on-warning", action="store_true",
        help="Exit 1 on WARNING in addition to BLOCKED",
    )

    args = parser.parse_args(argv)

    try:
        return _run(args)
    except _GateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code


def _run(args) -> int:
    if not args.quiet:
        print(f"[ci_gate] Loading decisions from: {args.decisions}")

    decisions = _load_decisions(args.decisions)

    if not args.quiet:
        print(f"[ci_gate] Loaded {len(decisions)} decision(s) for version: {args.agent_version}")

    cfg = _build_config(args.config)
    validator = PreflightValidator(cfg)

    if not args.quiet:
        print("[ci_gate] Running preflight validation...")

    report = validator.validate_batch(decisions, agent_version=args.agent_version)
    report_dict = _report_to_dict(report)
    json_output = json.dumps(report_dict, indent=2)
    print(json_output)

    if args.output:
        try:
            Path(args.output).write_text(json_output + "\n")
            if not args.quiet:
                print(f"[ci_gate] Report written to: {args.output}")
        except OSError as e:
            print(f"WARNING: Could not write report to {args.output!r}: {e}", file=sys.stderr)

    recommendation = report.recommendation

    if not args.quiet:
        print(f"\n[ci_gate] Recommendation: {recommendation}")
        for v in report.threshold_violations:
            print(f"  VIOLATION: {v}")
        for f in report.high_risk_failures:
            print(f"  HIGH-RISK FAILURE: {f}")

    if recommendation == "BLOCKED":
        if not args.quiet:
            print("[ci_gate] DEPLOYMENT BLOCKED — governance thresholds violated.", file=sys.stderr)
        return 1

    if recommendation == "WARNING" and args.fail_on_warning:
        if not args.quiet:
            print("[ci_gate] DEPLOYMENT FLAGGED (--fail-on-warning) — advisory issues present.",
                  file=sys.stderr)
        return 1

    if recommendation == "WARNING":
        if not args.quiet:
            print("[ci_gate] WARNING — advisory issues present; deployment continues.")
        return 2

    if not args.quiet:
        print("[ci_gate] SAFE TO DEPLOY.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
