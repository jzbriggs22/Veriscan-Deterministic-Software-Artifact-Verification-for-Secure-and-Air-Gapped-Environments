"""
Fixed 50-decision behavioral test dataset.

These fixtures are the governance regression suite — they must NEVER change
without a deliberate version bump. If these decisions start failing schema
validation or producing unexpected drift scores, the agent has regressed.

Dataset composition:
  - 10 billing disputes  (indices  0–9)
  - 10 fraud claims      (indices 10–19)
  - 10 policy-sensitive  (indices 20–29)
  - 10 routine           (indices 30–39)
  - 10 edge cases        (indices 40–49): boundary conditions, ambiguous
    category, confidence extremes, empty flags, very long decision text

Risk-level ground truth (used in behavioral assertions):
  - billing_dispute  → "high"   (financial harm if wrong)
  - fraud_claim      → "critical" (security / fraud if wrong)
  - policy_sensitive → "high"   (regulatory / legal risk)
  - routine          → "low"    (low harm if wrong)
  - edge_case        → varies   (see individual entries)

Expected outcomes for healthy-baseline assertions:
  - billing_dispute:  resolution_rate ≈ 0.70  (7/10 resolved)
  - fraud_claim:      error_rate < 0.20       (≤ 2/10 errors)
  - policy_sensitive: escalation_rate ≈ 0.30  (3/10 escalated)
  - routine:          resolution_rate ≈ 0.90  (9/10 resolved)
"""
from __future__ import annotations

from typing import Any

# Each entry is a dict valid for GovernanceDecision.model_validate()
# AND carries extra governance metadata used only in behavioral tests.
# Extra fields beyond the schema: _outcome (resolved|error|escalated|rejected),
# _expected_category (CaseCategory value), _description (human label)
FIXTURE_DECISIONS: list[dict[str, Any]] = [
    # ── Billing disputes (0–9) ────────────────────────────────────────────────
    {
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Issue full refund for the duplicate charge.",
        "confidence": 0.93,
        "flags": ["duplicate_charge", "first_offense"],
        "_outcome": "resolved",
        "_expected_category": "billing_dispute",
        "_description": "Clear duplicate charge — auto-refund",
    },
    {
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Escalate to billing team for manual review of the disputed subscription.",
        "confidence": 0.78,
        "flags": ["disputed_subscription", "high_value"],
        "_outcome": "escalated",
        "_expected_category": "billing_dispute",
        "_description": "High-value subscription dispute — escalate",
    },
    {
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Apply a 20% goodwill credit to the account.",
        "confidence": 0.85,
        "flags": ["service_outage", "long_term_customer"],
        "_outcome": "resolved",
        "_expected_category": "billing_dispute",
        "_description": "Service outage credit",
    },
    {
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Resolve by correcting the billing cycle date.",
        "confidence": 0.91,
        "flags": ["billing_cycle_error"],
        "_outcome": "resolved",
        "_expected_category": "billing_dispute",
        "_description": "Billing cycle correction",
    },
    {
        "case_category": "billing_dispute",
        "risk_level": "critical",
        "decision": "Escalate to fraud prevention; charge pattern resembles card testing.",
        "confidence": 0.88,
        "flags": ["card_testing_pattern", "multiple_small_charges"],
        "_outcome": "escalated",
        "_expected_category": "billing_dispute",
        "_description": "Billing dispute with fraud indicators",
    },
    {
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Reject refund request; charge is valid per terms of service.",
        "confidence": 0.82,
        "flags": ["policy_compliant_charge"],
        "_outcome": "rejected",
        "_expected_category": "billing_dispute",
        "_description": "Valid charge — reject refund",
    },
    {
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Issue partial refund for the unused portion of the annual plan.",
        "confidence": 0.87,
        "flags": ["prorated_refund", "annual_plan"],
        "_outcome": "resolved",
        "_expected_category": "billing_dispute",
        "_description": "Prorated refund for cancelled plan",
    },
    {
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Unable to process refund; payment gateway returned an error.",
        "confidence": 0.61,
        "flags": ["gateway_error", "retry_required"],
        "_outcome": "error",
        "_expected_category": "billing_dispute",
        "_description": "Gateway error during refund",
    },
    {
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Resolved: waived late fee as first-time exception.",
        "confidence": 0.94,
        "flags": ["late_fee_waiver", "first_exception"],
        "_outcome": "resolved",
        "_expected_category": "billing_dispute",
        "_description": "Late fee waiver",
    },
    {
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Escalate; customer claims charge is not from our company.",
        "confidence": 0.72,
        "flags": ["disputed_merchant", "possible_fraud"],
        "_outcome": "escalated",
        "_expected_category": "billing_dispute",
        "_description": "Disputed merchant identity",
    },
    # ── Fraud claims (10–19) ──────────────────────────────────────────────────
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Escalate: immediately freeze account pending fraud investigation.",
        "confidence": 0.97,
        "flags": ["account_takeover", "geo_anomaly", "new_device"],
        "_outcome": "escalated",
        "_expected_category": "fraud_claim",
        "_description": "Account takeover — freeze immediately",
    },
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Block and decline the transaction; flag for security review.",
        "confidence": 0.95,
        "flags": ["velocity_check_failed", "blacklisted_ip"],
        "_outcome": "rejected",
        "_expected_category": "fraud_claim",
        "_description": "High-velocity fraud transaction",
    },
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Escalate to fraud team; pattern matches known synthetic identity.",
        "confidence": 0.89,
        "flags": ["synthetic_identity", "address_mismatch"],
        "_outcome": "escalated",
        "_expected_category": "fraud_claim",
        "_description": "Synthetic identity fraud",
    },
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Resolved: false positive — transaction confirmed by customer via 2FA.",
        "confidence": 0.91,
        "flags": ["false_positive", "2fa_confirmed"],
        "_outcome": "resolved",
        "_expected_category": "fraud_claim",
        "_description": "Fraud claim false positive",
    },
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Unable to verify identity; escalate to human agent.",
        "confidence": 0.55,
        "flags": ["identity_verification_failed", "low_confidence"],
        "_outcome": "escalated",
        "_expected_category": "fraud_claim",
        "_description": "Identity verification failure",
    },
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Block card and initiate chargeback for unauthorized transaction.",
        "confidence": 0.93,
        "flags": ["unauthorized_transaction", "card_not_present"],
        "_outcome": "rejected",
        "_expected_category": "fraud_claim",
        "_description": "Unauthorized CNP transaction",
    },
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Error: fraud scoring service unavailable; cannot auto-process.",
        "confidence": 0.40,
        "flags": ["scoring_service_down", "manual_required"],
        "_outcome": "error",
        "_expected_category": "fraud_claim",
        "_description": "Fraud scoring service failure",
    },
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Escalate: device fingerprint matches three previous fraud accounts.",
        "confidence": 0.96,
        "flags": ["device_fingerprint_match", "repeat_offender"],
        "_outcome": "escalated",
        "_expected_category": "fraud_claim",
        "_description": "Device fingerprint fraud ring",
    },
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Resolved: legitimate travel pattern confirmed with customer.",
        "confidence": 0.88,
        "flags": ["geo_anomaly", "travel_confirmed"],
        "_outcome": "resolved",
        "_expected_category": "fraud_claim",
        "_description": "Legitimate geo anomaly — travel",
    },
    {
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Reject login attempt; MFA challenge threshold exceeded three times.",
        "confidence": 0.99,
        "flags": ["mfa_failed", "brute_force_attempt"],
        "_outcome": "rejected",
        "_expected_category": "fraud_claim",
        "_description": "MFA brute force rejection",
    },
    # ── Policy-sensitive (20–29) ──────────────────────────────────────────────
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Escalate to legal team; customer references potential GDPR breach.",
        "confidence": 0.90,
        "flags": ["gdpr_reference", "legal_escalation"],
        "_outcome": "escalated",
        "_expected_category": "policy_sensitive",
        "_description": "GDPR breach claim",
    },
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Resolved: provided data export per CCPA request within 45-day SLA.",
        "confidence": 0.95,
        "flags": ["ccpa_request", "data_export"],
        "_outcome": "resolved",
        "_expected_category": "policy_sensitive",
        "_description": "CCPA data export request",
    },
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Escalate: content moderation policy violation requires legal review.",
        "confidence": 0.83,
        "flags": ["content_violation", "legal_review"],
        "_outcome": "escalated",
        "_expected_category": "policy_sensitive",
        "_description": "Content moderation escalation",
    },
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Reject request; content violates acceptable use policy section 4.2.",
        "confidence": 0.91,
        "flags": ["aup_violation", "section_4_2"],
        "_outcome": "rejected",
        "_expected_category": "policy_sensitive",
        "_description": "AUP violation — reject",
    },
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Escalate to compliance: HIPAA-adjacent data handling concern.",
        "confidence": 0.87,
        "flags": ["hipaa_adjacent", "compliance_review"],
        "_outcome": "escalated",
        "_expected_category": "policy_sensitive",
        "_description": "HIPAA-adjacent compliance concern",
    },
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Resolved: verified consent form on file; process the request.",
        "confidence": 0.93,
        "flags": ["consent_verified"],
        "_outcome": "resolved",
        "_expected_category": "policy_sensitive",
        "_description": "Consent verified — process",
    },
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Error: policy lookup service returned conflicting rules; cannot auto-resolve.",
        "confidence": 0.45,
        "flags": ["policy_conflict", "manual_required"],
        "_outcome": "error",
        "_expected_category": "policy_sensitive",
        "_description": "Conflicting policy rules — error",
    },
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Resolved: right-to-deletion request processed per internal SOP.",
        "confidence": 0.92,
        "flags": ["right_to_deletion", "sop_followed"],
        "_outcome": "resolved",
        "_expected_category": "policy_sensitive",
        "_description": "Right-to-deletion request",
    },
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Escalate: attorney representation letter received.",
        "confidence": 0.98,
        "flags": ["attorney_letter", "legal_hold"],
        "_outcome": "escalated",
        "_expected_category": "policy_sensitive",
        "_description": "Attorney representation — legal hold",
    },
    {
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": "Reject: request falls outside scope of current regulatory guidance.",
        "confidence": 0.79,
        "flags": ["out_of_scope", "regulatory_guidance"],
        "_outcome": "rejected",
        "_expected_category": "policy_sensitive",
        "_description": "Out-of-scope regulatory request",
    },
    # ── Routine (30–39) ───────────────────────────────────────────────────────
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Password reset link sent to verified email.",
        "confidence": 0.99,
        "flags": [],
        "_outcome": "resolved",
        "_expected_category": "routine",
        "_description": "Password reset",
    },
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Account preferences updated as requested.",
        "confidence": 0.98,
        "flags": [],
        "_outcome": "resolved",
        "_expected_category": "routine",
        "_description": "Preferences update",
    },
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "FAQ link provided for shipping policy inquiry.",
        "confidence": 0.97,
        "flags": [],
        "_outcome": "resolved",
        "_expected_category": "routine",
        "_description": "Shipping FAQ",
    },
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Order status confirmed: shipped, tracking number provided.",
        "confidence": 0.99,
        "flags": [],
        "_outcome": "resolved",
        "_expected_category": "routine",
        "_description": "Order status check",
    },
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Account email address updated and confirmation sent.",
        "confidence": 0.96,
        "flags": [],
        "_outcome": "resolved",
        "_expected_category": "routine",
        "_description": "Email address change",
    },
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Resolved: explained subscription auto-renewal policy.",
        "confidence": 0.95,
        "flags": [],
        "_outcome": "resolved",
        "_expected_category": "routine",
        "_description": "Auto-renewal explanation",
    },
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Escalate: customer asked to speak to a human agent.",
        "confidence": 0.99,
        "flags": ["human_requested"],
        "_outcome": "escalated",
        "_expected_category": "routine",
        "_description": "Human escalation request",
    },
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Error: account lookup failed; user not found in system.",
        "confidence": 0.30,
        "flags": ["lookup_failed"],
        "_outcome": "error",
        "_expected_category": "routine",
        "_description": "Account not found — system error",
    },
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Resolved: plan downgrade processed for next billing cycle.",
        "confidence": 0.97,
        "flags": [],
        "_outcome": "resolved",
        "_expected_category": "routine",
        "_description": "Plan downgrade",
    },
    {
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Resolved: closed account at customer request.",
        "confidence": 0.98,
        "flags": ["account_closure"],
        "_outcome": "resolved",
        "_expected_category": "routine",
        "_description": "Account closure",
    },
    # ── Edge cases (40–49) ────────────────────────────────────────────────────
    {
        # Boundary: confidence exactly at minimum valid value
        "case_category": "billing_dispute",
        "risk_level": "high",
        "decision": "Very uncertain — escalate for human review.",
        "confidence": 0.0,
        "flags": ["very_low_confidence"],
        "_outcome": "escalated",
        "_expected_category": "billing_dispute",
        "_description": "Edge: minimum confidence",
    },
    {
        # Boundary: confidence exactly at maximum valid value
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Block confirmed fraudulent transaction.",
        "confidence": 1.0,
        "flags": ["max_confidence"],
        "_outcome": "rejected",
        "_expected_category": "fraud_claim",
        "_description": "Edge: maximum confidence",
    },
    {
        # Boundary: empty flags list
        "case_category": "fraud_claim",
        "risk_level": "high",
        "decision": "Escalate for review; no specific flags raised.",
        "confidence": 0.70,
        "flags": [],
        "_outcome": "escalated",
        "_expected_category": "fraud_claim",
        "_description": "Edge: empty flags",
    },
    {
        # Boundary: category normalisation (space → underscore)
        "case_category": "billing dispute",
        "risk_level": "high",
        "decision": "Resolved billing issue.",
        "confidence": 0.85,
        "flags": [],
        "_outcome": "resolved",
        "_expected_category": "billing_dispute",
        "_description": "Edge: category with space (normalization)",
    },
    {
        # Boundary: category with dash
        "case_category": "fraud-claim",
        "risk_level": "critical",
        "decision": "Escalate: freeze account.",
        "confidence": 0.92,
        "flags": ["geo_anomaly"],
        "_outcome": "escalated",
        "_expected_category": "fraud_claim",
        "_description": "Edge: category with dash (normalization)",
    },
    {
        # Edge: unknown category + high risk → ingestor must handle gracefully
        "case_category": "unknown",
        "risk_level": "high",
        "decision": "Escalate to human; could not determine case type.",
        "confidence": 0.50,
        "flags": ["unknown_category"],
        "_outcome": "escalated",
        "_expected_category": "unknown",
        "_description": "Edge: unknown category",
    },
    {
        # Edge: very long decision text (should not break parsing)
        "case_category": "policy_sensitive",
        "risk_level": "high",
        "decision": (
            "After reviewing the customer's request in detail, consulting the relevant "
            "regulatory guidelines, cross-referencing with our internal compliance "
            "documentation, and verifying the customer's identity through three separate "
            "verification channels, we have determined that the appropriate course of "
            "action is to escalate this matter to the legal and compliance team for "
            "further review, as the request touches on areas that require specialist "
            "knowledge and may have regulatory implications that extend beyond the "
            "scope of standard first-line support."
        ),
        "confidence": 0.80,
        "flags": ["complex_regulatory", "multi_jurisdiction", "specialist_required"],
        "_outcome": "escalated",
        "_expected_category": "policy_sensitive",
        "_description": "Edge: very long decision text",
    },
    {
        # Edge: multiple high-risk flags, mixed risk signals
        "case_category": "billing_dispute",
        "risk_level": "critical",
        "decision": "Escalate immediately; multiple risk flags active.",
        "confidence": 0.88,
        "flags": [
            "high_value", "repeated_dispute", "account_age_lt_30d",
            "international_card", "vpn_detected",
        ],
        "_outcome": "escalated",
        "_expected_category": "billing_dispute",
        "_description": "Edge: many risk flags",
    },
    {
        # Edge: confidence above 1.0 (clamped by validator)
        "case_category": "routine",
        "risk_level": "low",
        "decision": "Resolved account inquiry.",
        "confidence": 1.001,   # will be clamped to 1.0 by field_validator
        "flags": [],
        "_outcome": "resolved",
        "_expected_category": "routine",
        "_description": "Edge: confidence > 1.0 (clamped)",
    },
    {
        # Edge: decision text that is pure escalation verb
        "case_category": "fraud_claim",
        "risk_level": "critical",
        "decision": "Escalate.",
        "confidence": 0.75,
        "flags": ["minimal_decision_text"],
        "_outcome": "escalated",
        "_expected_category": "fraud_claim",
        "_description": "Edge: minimal decision text",
    },
]

# Sanity check: exactly 50 fixtures
assert len(FIXTURE_DECISIONS) == 50, f"Expected 50 fixtures, got {len(FIXTURE_DECISIONS)}"

# Convenience views for tests
BILLING_FIXTURES = FIXTURE_DECISIONS[0:10]
FRAUD_FIXTURES = FIXTURE_DECISIONS[10:20]
POLICY_FIXTURES = FIXTURE_DECISIONS[20:30]
ROUTINE_FIXTURES = FIXTURE_DECISIONS[30:40]
EDGE_FIXTURES = FIXTURE_DECISIONS[40:50]

# High-risk fixtures (billing + fraud + policy)
HIGH_RISK_FIXTURES = BILLING_FIXTURES + FRAUD_FIXTURES + POLICY_FIXTURES

# Schema-only dicts (strip private _ keys) for GovernanceDecision.model_validate()
SCHEMA_DICTS = [
    {k: v for k, v in d.items() if not k.startswith("_")}
    for d in FIXTURE_DECISIONS
]
