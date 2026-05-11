"""Tests for governance config loading and validation."""
import pytest

from src.governance.config import DriftThresholds, GovernanceConfig
from src.governance.schema import CaseCategory


def test_default_config_is_valid():
    config = GovernanceConfig.default()
    # Should not raise
    config.validate()


def test_default_config_has_three_high_risk_categories():
    config = GovernanceConfig.default()
    cats = {hrc.category for hrc in config.high_risk_categories}
    assert CaseCategory.BILLING_DISPUTE in cats
    assert CaseCategory.FRAUD_CLAIM in cats
    assert CaseCategory.POLICY_SENSITIVE in cats


def test_thresholds_for_known_category():
    config = GovernanceConfig.default()
    t = config.thresholds_for(CaseCategory.FRAUD_CLAIM)
    # Fraud has tightest thresholds
    assert t.critical_score <= 0.65
    assert t.max_error_rate <= 0.12


def test_thresholds_for_unknown_category_returns_default():
    config = GovernanceConfig.default()
    t = config.thresholds_for(CaseCategory.UNKNOWN)
    assert t == config.default_thresholds


def test_weight_for_fraud_is_highest():
    config = GovernanceConfig.default()
    fraud_weight = config.weight_for(CaseCategory.FRAUD_CLAIM)
    billing_weight = config.weight_for(CaseCategory.BILLING_DISPUTE)
    assert fraud_weight > billing_weight


def test_weight_for_unknown_returns_1():
    config = GovernanceConfig.default()
    assert config.weight_for(CaseCategory.UNKNOWN) == 1.0


def test_baseline_window_must_be_larger_than_detection():
    config = GovernanceConfig.default()
    config.baseline_window = 5
    config.detection_window = 10
    with pytest.raises(ValueError, match="baseline_window"):
        config.validate()


def test_baseline_window_minimum():
    config = GovernanceConfig.default()
    config.baseline_window = 3
    with pytest.raises(ValueError, match="baseline_window"):
        config.validate()


def test_detection_window_minimum():
    config = GovernanceConfig.default()
    config.detection_window = 2
    config.baseline_window = 10  # satisfies baseline >= 10 and baseline >= detection
    with pytest.raises(ValueError, match="detection_window"):
        config.validate()


def test_rollback_rules_parsed():
    config = GovernanceConfig.default()
    assert len(config.rollback_rules) >= 2
    for rule in config.rollback_rules:
        assert rule._metric != ""
        assert rule._operator != ""
        assert rule._threshold > 0


def test_rollback_rule_condition_bad_syntax():
    from src.governance.config import RollbackRule
    from src.governance.schema import AlertSeverity
    config = GovernanceConfig.default()
    config.rollback_rules.append(
        RollbackRule(
            description="broken",
            condition="this is not a valid condition",
            severity=AlertSeverity.CRITICAL,
        )
    )
    with pytest.raises(ValueError, match="Cannot parse rollback rule condition"):
        config.validate()


def test_rollback_rule_matches_drift_score():
    from src.governance.config import RollbackRule
    from src.governance.schema import AlertSeverity
    rule = RollbackRule(
        description="test",
        condition="drift_score > 0.70",
        severity=AlertSeverity.CRITICAL,
    )
    # Parse the condition
    rule._metric = "drift_score"
    rule._operator = ">"
    rule._threshold = 0.70
    assert rule.matches(drift_score=0.80, error_rate=0.05, category=CaseCategory.BILLING_DISPUTE, is_high_risk=True)
    assert not rule.matches(drift_score=0.65, error_rate=0.05, category=CaseCategory.BILLING_DISPUTE, is_high_risk=True)


def test_from_yaml_loads_correctly(tmp_path):
    yaml_content = """
baseline_window: 80
detection_window: 15
default_thresholds:
  warning_score: 0.35
  critical_score: 0.65
  min_baseline_size: 25
  min_detection_size: 8
  max_error_rate: 0.10
high_risk_categories:
  - category: billing_dispute
    display_name: "Billing"
    weight: 1.3
    thresholds:
      warning_score: 0.30
      critical_score: 0.60
      min_baseline_size: 15
      min_detection_size: 5
      max_error_rate: 0.10
rollback_rules:
  - description: "High error rate"
    condition: "error_rate > 0.10"
    severity: critical
"""
    p = tmp_path / "gov.yaml"
    p.write_text(yaml_content)
    config = GovernanceConfig.from_yaml(str(p))
    assert config.baseline_window == 80
    assert config.detection_window == 15
    assert len(config.high_risk_categories) == 1
    assert config.high_risk_categories[0].category == CaseCategory.BILLING_DISPUTE
    assert config.high_risk_categories[0].weight == 1.3
    assert config.rollback_rules[0]._threshold == 0.10
