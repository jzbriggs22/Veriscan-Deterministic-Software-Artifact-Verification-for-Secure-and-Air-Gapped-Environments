"""
Single source of truth for deriving overall governance status.

Before this module existed, four surfaces (the JSON report endpoint, the
status endpoint, the terminal dashboard, and the HTML report) each derived
"is the agent safe?" with their own logic — two of them with hardcoded
thresholds that ignored per-category configuration, and one that ignored
active rollbacks entirely.  Every surface now delegates here.

Precedence:
  1. An active rollback always wins → ROLLBACK_TRIGGERED.
  2. Any category at/above its configured critical_score → CRITICAL.
  3. Any category at/above its configured warning_score → DRIFTING.
  4. Otherwise → HEALTHY.

Results flagged insufficient_data never contribute to the verdict.
"""
from __future__ import annotations

from .config import GovernanceConfig
from .schema import DriftResult, GovernanceStatus


def compute_status(
    drift_results: list[DriftResult],
    config: GovernanceConfig,
    rollback_active: bool,
) -> GovernanceStatus:
    """Derive the overall governance status from one detection cycle."""
    if rollback_active:
        return GovernanceStatus.ROLLBACK_TRIGGERED

    status = GovernanceStatus.HEALTHY
    for result in drift_results:
        if result.insufficient_data:
            continue
        thresholds = config.thresholds_for(result.category)
        if result.drift_score >= thresholds.critical_score:
            return GovernanceStatus.CRITICAL
        if result.drift_score >= thresholds.warning_score:
            status = GovernanceStatus.DRIFTING
    return status
