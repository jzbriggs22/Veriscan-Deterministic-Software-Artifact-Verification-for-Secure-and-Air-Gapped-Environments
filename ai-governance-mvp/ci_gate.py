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
  --agent-version VER    Version string for this deployment (default: "unknown")
  --output FILE          Write JSON report to FILE in addition to stdout
  --quiet                Suppress non-JSON output (still writes JSON to stdout)
  --fail-on-warning      Exit 1 on WARNING as well as BLOCKED

Environment variables (override config defaults):
  GOVERNANCE_MIN_DETECTION_SIZE   Minimum decisions per category (int)
  GOVERNANCE_ERROR_RATE_THRESHOLD Max tolerated error rate (float, 0–1)
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
from src.governance.structured import GovernanceDecision, StructuredOutputError


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


def _die(msg: str, exit_code: int = 3) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(exit_code)


def _build_config() -> GovernanceConfig:
    cfg = GovernanceConfig.default()
    env_min = os.environ.get("GOVERNANCE_MIN_DETECTION_SIZE")
    env_err = os.environ.get("GOVERNANCE_ERROR_RATE_THRESHOLD")
    if env_min is not None:
        try:
            cfg = GovernanceConfig(
                min_detection_size=int(env_min),
                error_rate_threshold=cfg.error_rate_threshold,
                drift_score_warning=cfg.drift_score_warning,
                drift_score_critical=cfg.drift_score_critical,
                rollback_drift_score=cfg.rollback_drift_score,
                min_baseline_size=cfg.min_baseline_size,
                baseline_window_days=cfg.baseline_window_days,
                detection_window_hours=cfg.detection_window_hours,
            )
        except (ValueError, TypeError) as e:
            _die(f"Invalid GOVERNANCE_MIN_DETECTION_SIZE: {e}", exit_code=3)
    if env_err is not None:
        try:
            cfg = GovernanceConfig(
                min_detection_size=cfg.min_detection_size,
                error_rate_threshold=float(env_err),
                drift_score_warning=cfg.drift_score_warning,
                drift_score_critical=cfg.drift_score_critical,
                rollback_drift_score=cfg.rollback_drift_score,
                min_baseline_size=cfg.min_baseline_size,
                baseline_window_days=cfg.baseline_window_days,
                detection_window_hours=cfg.detection_window_hours,
            )
        except (ValueError, TypeError) as e:
            _die(f"Invalid GOVERNANCE_ERROR_RATE_THRESHOLD: {e}", exit_code=3)
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
                "high_risk_count": r.high_risk_count,
                "error_rate": r.error_rate,
                "resolution_rate": r.resolution_rate,
                "mean_confidence": r.mean_confidence,
                "schema_errors": r.schema_errors,
                "issues": r.issues,
                "passed": r.passed,
            }
            for r in report.category_results
        ],
    }


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
        "--agent-version", default="unknown", metavar="VER",
        help="Version string for this deployment (default: unknown)",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Write JSON report to FILE",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress non-JSON output",
    )
    parser.add_argument(
        "--fail-on-warning", action="store_true",
        help="Exit 1 on WARNING in addition to BLOCKED",
    )

    args = parser.parse_args(argv)

    if not args.quiet:
        print(f"[ci_gate] Loading decisions from: {args.decisions}")

    decisions = _load_decisions(args.decisions)

    if not args.quiet:
        print(f"[ci_gate] Loaded {len(decisions)} decision(s) for version: {args.agent_version}")

    cfg = _build_config()
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
        if report.threshold_violations:
            for v in report.threshold_violations:
                print(f"  VIOLATION: {v}")
        if report.high_risk_failures:
            for f in report.high_risk_failures:
                print(f"  HIGH-RISK FAILURE: {f}")

    if recommendation == "BLOCKED":
        if not args.quiet:
            print("[ci_gate] DEPLOYMENT BLOCKED — governance thresholds violated.", file=sys.stderr)
        return 1

    if recommendation == "WARNING" and args.fail_on_warning:
        if not args.quiet:
            print("[ci_gate] DEPLOYMENT FLAGGED (--fail-on-warning) — advisory issues present.", file=sys.stderr)
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
