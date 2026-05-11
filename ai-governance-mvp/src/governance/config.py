"""Governance configuration: drift thresholds, high-risk patterns, rollback rules."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from .schema import AlertSeverity, CaseCategory


@dataclass
class DriftThresholds:
    """Per-severity drift score thresholds and sample-size requirements."""
    warning_score: float = 0.40   # alert at WARNING level
    critical_score: float = 0.70  # alert at CRITICAL level
    min_baseline_size: int = 30   # minimum decisions to establish baseline
    min_detection_size: int = 10  # minimum decisions in recent window to run detection
    max_error_rate: float = 0.15  # absolute error-rate ceiling before critical alert


@dataclass
class HighRiskCategoryConfig:
    category: CaseCategory
    display_name: str
    weight: float = 1.0           # multiplier applied to drift scores for this category
    thresholds: DriftThresholds = field(default_factory=DriftThresholds)


@dataclass
class RollbackRule:
    description: str
    condition: str                 # human-readable; evaluated by RollbackEngine
    severity: AlertSeverity = AlertSeverity.CRITICAL
    # Parsed fields — populated by GovernanceConfig.validate()
    _metric: str = field(default="", repr=False)
    _operator: str = field(default="", repr=False)
    _threshold: float = field(default=0.0, repr=False)

    def matches(
        self,
        drift_score: float,
        error_rate: Optional[float],
        category: CaseCategory,
        is_high_risk: bool,
    ) -> bool:
        m = self._metric
        op = self._operator
        val = self._threshold
        subject = {
            "drift_score": drift_score,
            "error_rate": error_rate or 0.0,
        }.get(m)
        if subject is None:
            return False
        if op == ">":
            return subject > val
        if op == ">=":
            return subject >= val
        if op == "<":
            return subject < val
        if op == "<=":
            return subject <= val
        return False


_CONDITION_RE = re.compile(
    r"(?P<metric>\w+)\s*(?P<op>[><=!]+)\s*(?P<value>[\d.]+)"
)


@dataclass
class TimeWindowConfig:
    """Time-anchored detection windows (alternative to count-based windows).

    Baseline: [now - baseline_lookback_days, now - baseline_exclusion_hours)
    Detection: [now - detection_hours, now)

    The exclusion gap (baseline_exclusion_hours) prevents drifted recent data
    from contaminating the baseline distribution.
    """
    baseline_lookback_days: int = 30   # how far back the baseline extends
    baseline_exclusion_hours: int = 168  # gap between baseline end and now (7 days)
    detection_hours: int = 24          # how recent the detection window is
    use_time_windows: bool = True      # when False, fall back to count-based windows


@dataclass
class GovernanceConfig:
    # Count-based detection windows (used when use_time_windows=False)
    baseline_window: int = 100        # decisions per category to build baseline
    detection_window: int = 20        # most-recent decisions per category to compare

    # Time-anchored window config (preferred)
    time_window: TimeWindowConfig = field(default_factory=TimeWindowConfig)

    # High-risk category definitions
    high_risk_categories: list[HighRiskCategoryConfig] = field(default_factory=list)

    # Global default thresholds (overridden per-category)
    default_thresholds: DriftThresholds = field(default_factory=DriftThresholds)

    # URL / keyword patterns for case categorization (applied to case_text)
    category_patterns: dict[str, list[str]] = field(default_factory=dict)

    # Rollback rules evaluated in order; first match wins
    rollback_rules: list[RollbackRule] = field(default_factory=list)

    def validate(self) -> None:
        if self.baseline_window < 10:
            raise ValueError("baseline_window must be >= 10")
        if self.detection_window < 5:
            raise ValueError("detection_window must be >= 5")
        if self.baseline_window < self.detection_window:
            raise ValueError("baseline_window must be >= detection_window")
        for rule in self.rollback_rules:
            m = _CONDITION_RE.match(rule.condition.strip())
            if not m:
                raise ValueError(f"Cannot parse rollback rule condition: {rule.condition!r}")
            rule._metric = m.group("metric")
            rule._operator = m.group("op")
            rule._threshold = float(m.group("value"))

    def thresholds_for(self, category: CaseCategory) -> DriftThresholds:
        for hrc in self.high_risk_categories:
            if hrc.category == category:
                return hrc.thresholds
        return self.default_thresholds

    def weight_for(self, category: CaseCategory) -> float:
        for hrc in self.high_risk_categories:
            if hrc.category == category:
                return hrc.weight
        return 1.0

    @classmethod
    def default(cls) -> "GovernanceConfig":
        cfg = cls(
            baseline_window=100,
            detection_window=20,
            high_risk_categories=[
                HighRiskCategoryConfig(
                    category=CaseCategory.BILLING_DISPUTE,
                    display_name="Billing Disputes",
                    weight=1.5,
                    thresholds=DriftThresholds(
                        warning_score=0.35,
                        critical_score=0.65,
                        min_baseline_size=20,
                        min_detection_size=5,
                        max_error_rate=0.12,
                    ),
                ),
                HighRiskCategoryConfig(
                    category=CaseCategory.FRAUD_CLAIM,
                    display_name="Fraud Claims",
                    weight=2.0,
                    thresholds=DriftThresholds(
                        warning_score=0.30,
                        critical_score=0.60,
                        min_baseline_size=15,
                        min_detection_size=5,
                        max_error_rate=0.10,
                    ),
                ),
                HighRiskCategoryConfig(
                    category=CaseCategory.POLICY_SENSITIVE,
                    display_name="Policy-Sensitive",
                    weight=1.2,
                    thresholds=DriftThresholds(
                        warning_score=0.40,
                        critical_score=0.70,
                        min_baseline_size=20,
                        min_detection_size=5,
                        max_error_rate=0.15,
                    ),
                ),
            ],
            category_patterns={
                "billing_dispute": [
                    r"(?i)(billing|charge|invoice|refund|overcharg|credit\s+card|payment\s+dispute)",
                ],
                "fraud_claim": [
                    r"(?i)(fraud|unauthori[zs]ed|scam|stolen|identity\s+theft|suspicious\s+charge)",
                ],
                "policy_sensitive": [
                    r"(?i)(legal|compliance|regulator|policy\s+violat|gdpr|hipaa|lawsuit|attorney)",
                ],
            },
            rollback_rules=[
                RollbackRule(
                    description="Error rate on any high-risk category exceeds 15%",
                    condition="error_rate > 0.15",
                    severity=AlertSeverity.CRITICAL,
                ),
                RollbackRule(
                    description="Drift score on high-risk category exceeds critical threshold",
                    condition="drift_score > 0.70",
                    severity=AlertSeverity.CRITICAL,
                ),
            ],
        )
        cfg.validate()
        return cfg

    @classmethod
    def from_yaml(cls, path: str | Path) -> "GovernanceConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        tw_data = data.get("time_window", {})
        cfg = cls(
            baseline_window=data.get("baseline_window", 100),
            detection_window=data.get("detection_window", 20),
            time_window=TimeWindowConfig(
                baseline_lookback_days=tw_data.get("baseline_lookback_days", 30),
                baseline_exclusion_hours=tw_data.get("baseline_exclusion_hours", 168),
                detection_hours=tw_data.get("detection_hours", 24),
                use_time_windows=tw_data.get("use_time_windows", True),
            ),
        )
        tdata = data.get("default_thresholds", {})
        cfg.default_thresholds = DriftThresholds(
            warning_score=tdata.get("warning_score", 0.40),
            critical_score=tdata.get("critical_score", 0.70),
            min_baseline_size=tdata.get("min_baseline_size", 30),
            min_detection_size=tdata.get("min_detection_size", 10),
            max_error_rate=tdata.get("max_error_rate", 0.15),
        )
        for hrc_data in data.get("high_risk_categories", []):
            cat = CaseCategory(hrc_data["category"])
            t = hrc_data.get("thresholds", {})
            cfg.high_risk_categories.append(
                HighRiskCategoryConfig(
                    category=cat,
                    display_name=hrc_data.get("display_name", cat.value),
                    weight=hrc_data.get("weight", 1.0),
                    thresholds=DriftThresholds(
                        warning_score=t.get("warning_score", cfg.default_thresholds.warning_score),
                        critical_score=t.get("critical_score", cfg.default_thresholds.critical_score),
                        min_baseline_size=t.get("min_baseline_size", cfg.default_thresholds.min_baseline_size),
                        min_detection_size=t.get("min_detection_size", cfg.default_thresholds.min_detection_size),
                        max_error_rate=t.get("max_error_rate", cfg.default_thresholds.max_error_rate),
                    ),
                )
            )
        cfg.category_patterns = data.get("category_patterns", {})
        for rule_data in data.get("rollback_rules", []):
            cfg.rollback_rules.append(
                RollbackRule(
                    description=rule_data["description"],
                    condition=rule_data["condition"],
                    severity=AlertSeverity(rule_data.get("severity", "critical")),
                )
            )
        cfg.validate()
        return cfg
