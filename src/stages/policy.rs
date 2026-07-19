/// Policy decision stage: applies the decision matrix to pipeline results.
///
/// Evaluates rules in declared order (first match wins). Every applied rule
/// is recorded in the decision trace — the audit trail that explains exactly
/// why a verdict was reached.
///
/// No heuristic guessing: each rule condition maps to a discrete, observable
/// outcome from an upstream stage.
use crate::config::{Policy, RuleCondition, RuleVerdict};
use crate::error::VeriError;
use crate::evidence::{
    EvidenceItem, MalwareResult, PipelineResults, ReputationResult, SignatureResult,
    VerificationStatus,
};
use std::collections::HashMap;
use tracing::{info, warn};

/// A single entry in the decision trace.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceEntry {
    pub rule_description: String,
    pub condition: String,
    pub matched: bool,
    pub verdict: Option<String>,
}

/// Result of the policy decision stage.
#[derive(Debug)]
pub struct PolicyResult {
    pub status: VerificationStatus,
    pub decision_trace: Vec<TraceEntry>,
    pub evidence: Vec<EvidenceItem>,
}

/// Evaluate the policy against collected pipeline results.
pub fn evaluate(results: &PipelineResults, policy: &Policy) -> Result<PolicyResult, VeriError> {
    info!(stage = "policy", policy = %policy.name, "Evaluating policy");

    let mut trace: Vec<TraceEntry> = Vec::new();
    let mut final_verdict: Option<VerificationStatus> = None;
    let mut failing_reasons: Vec<String> = Vec::new();

    // ── Hard-wired mandatory checks ─────────────────────────────────────────
    // These checks cannot be disabled by any policy configuration. They
    // represent absolute security invariants.

    // 1. Malware detection is always fatal.
    if let MalwareResult::Detected { ref detections, .. } = results.malware_status {
        let reason = format!("Malware detected by scanner: {}", detections.join(", "));
        warn!(reason = %reason, "MANDATORY FAIL: malware detected");
        trace.push(TraceEntry {
            rule_description: "[MANDATORY] Malware detected".to_string(),
            condition: "MalwareDetected".to_string(),
            matched: true,
            verdict: Some("Failed".to_string()),
        });
        final_verdict = Some(VerificationStatus::Failed {
            reason: reason.clone(),
            evidence: vec![],
        });
        failing_reasons.push(reason);
    } else {
        trace.push(TraceEntry {
            rule_description: "[MANDATORY] Malware not detected".to_string(),
            condition: "MalwareDetected".to_string(),
            matched: false,
            verdict: None,
        });
    }

    // 2. Reputation malicious is always fatal.
    if let ReputationResult::Malicious {
        engines_detected,
        engines_total,
        ..
    } = &results.reputation
    {
        let reason = format!(
            "Reputation: {}/{} engines flagged artifact as malicious",
            engines_detected, engines_total
        );
        warn!(reason = %reason, "MANDATORY FAIL: reputation malicious");
        trace.push(TraceEntry {
            rule_description: "[MANDATORY] Reputation malicious".to_string(),
            condition: "ReputationMalicious".to_string(),
            matched: true,
            verdict: Some("Failed".to_string()),
        });
        if final_verdict.is_none() {
            final_verdict = Some(VerificationStatus::Failed {
                reason: reason.clone(),
                evidence: vec![],
            });
        }
        failing_reasons.push(reason);
    } else {
        trace.push(TraceEntry {
            rule_description: "[MANDATORY] Reputation not malicious".to_string(),
            condition: "ReputationMalicious".to_string(),
            matched: false,
            verdict: None,
        });
    }

    // ── Configurable rule evaluation ────────────────────────────────────────
    for rule in &policy.decision_matrix {
        let condition_name = format!("{:?}", rule.condition);
        let matched = evaluate_condition(&rule.condition, results, policy);

        let applied_verdict = if matched { Some(&rule.verdict) } else { None };

        trace.push(TraceEntry {
            rule_description: rule.description.clone(),
            condition: condition_name,
            matched,
            verdict: applied_verdict.map(|v| format!("{:?}", v)),
        });

        if matched && final_verdict.is_none() {
            match rule.verdict {
                RuleVerdict::Failed => {
                    let reason = rule.description.clone();
                    failing_reasons.push(reason.clone());
                    final_verdict = Some(VerificationStatus::Failed {
                        reason,
                        evidence: vec![],
                    });
                }
                RuleVerdict::Unverified => {
                    let reason = rule.description.clone();
                    final_verdict = Some(VerificationStatus::Unverified {
                        reason,
                        evidence: vec![],
                    });
                }
                RuleVerdict::Verified => {
                    final_verdict = Some(VerificationStatus::Verified);
                }
            }
        }
    }

    // ── Policy-level checks (not in decision matrix) ────────────────────────
    check_signature_policy(
        results,
        policy,
        &mut trace,
        &mut final_verdict,
        &mut failing_reasons,
    );
    check_file_type_policy(
        results,
        policy,
        &mut trace,
        &mut final_verdict,
        &mut failing_reasons,
    );
    check_executable_policy(
        results,
        policy,
        &mut trace,
        &mut final_verdict,
        &mut failing_reasons,
    );
    check_malware_availability_policy(results, policy, &mut trace, &mut final_verdict);
    check_reputation_availability_policy(results, policy, &mut trace, &mut final_verdict);
    check_sbom_policy(results, policy, &mut trace, &mut final_verdict);

    // ── Final verdict fallthrough ───────────────────────────────────────────
    let status = final_verdict.unwrap_or(VerificationStatus::Verified);
    info!(stage = "policy", verdict = %status.label(), "Policy evaluation complete");

    let evidence = build_evidence(policy, &trace, &status);
    Ok(PolicyResult {
        status,
        decision_trace: trace,
        evidence: vec![evidence],
    })
}

fn evaluate_condition(
    condition: &RuleCondition,
    results: &PipelineResults,
    policy: &Policy,
) -> bool {
    match condition {
        RuleCondition::MalwareDetected => {
            matches!(results.malware_status, MalwareResult::Detected { .. })
        }
        RuleCondition::SignatureMissing => {
            matches!(results.signature_status, SignatureResult::Missing)
        }
        RuleCondition::SignatureInvalid => {
            matches!(results.signature_status, SignatureResult::Invalid { .. })
        }
        RuleCondition::SignerNotAllowed => {
            matches!(
                results.signature_status,
                SignatureResult::SignerNotAllowed { .. }
            )
        }
        RuleCondition::ChecksumMismatch => {
            results.expected_sha256_matched == Some(false)
                || results.expected_sha512_matched == Some(false)
        }
        RuleCondition::HighEntropy => results.inspection.entropy_flagged,
        RuleCondition::DeniedFileType => policy
            .deny_file_types
            .iter()
            .any(|denied| results.file_type.contains(denied.as_str())),
        RuleCondition::ReputationMalicious => {
            matches!(results.reputation, ReputationResult::Malicious { .. })
        }
        RuleCondition::ReputationUnavailable => matches!(
            results.reputation,
            ReputationResult::Unknown { .. }
                | ReputationResult::Unavailable { .. }
                | ReputationResult::ApiKeyMissing
        ),
        RuleCondition::MalwareScanUnavailable => {
            matches!(
                results.malware_status,
                MalwareResult::ToolMissing { .. } | MalwareResult::ScanError { .. }
            )
        }
        RuleCondition::SbomMissing => policy.require_sbom,
        RuleCondition::Always => true,
    }
}

fn check_signature_policy(
    results: &PipelineResults,
    policy: &Policy,
    trace: &mut Vec<TraceEntry>,
    final_verdict: &mut Option<VerificationStatus>,
    failing_reasons: &mut Vec<String>,
) {
    if !policy.require_signature {
        trace.push(TraceEntry {
            rule_description: "Signature not required by policy".to_string(),
            condition: "SignatureRequired".to_string(),
            matched: false,
            verdict: None,
        });
        return;
    }

    match &results.signature_status {
        SignatureResult::Verified { .. } => {
            trace.push(TraceEntry {
                rule_description: "Signature verified (policy requires it)".to_string(),
                condition: "SignatureRequired".to_string(),
                matched: true,
                verdict: Some("Verified".to_string()),
            });
        }
        SignatureResult::Missing => {
            let reason = "Signature required by policy but not present".to_string();
            trace.push(TraceEntry {
                rule_description: reason.clone(),
                condition: "SignatureRequired".to_string(),
                matched: true,
                verdict: Some("Failed".to_string()),
            });
            if final_verdict.is_none() {
                failing_reasons.push(reason.clone());
                *final_verdict = Some(VerificationStatus::Failed {
                    reason,
                    evidence: vec![],
                });
            }
        }
        SignatureResult::Invalid { reason } => {
            let msg = format!("Signature invalid: {}", reason);
            trace.push(TraceEntry {
                rule_description: msg.clone(),
                condition: "SignatureRequired".to_string(),
                matched: true,
                verdict: Some("Failed".to_string()),
            });
            if final_verdict.is_none() {
                failing_reasons.push(msg.clone());
                *final_verdict = Some(VerificationStatus::Failed {
                    reason: msg,
                    evidence: vec![],
                });
            }
        }
        SignatureResult::SignerNotAllowed { fingerprint } => {
            let reason = format!("Signer '{}' not in allow list", fingerprint);
            trace.push(TraceEntry {
                rule_description: reason.clone(),
                condition: "SignatureRequired".to_string(),
                matched: true,
                verdict: Some("Failed".to_string()),
            });
            if final_verdict.is_none() {
                failing_reasons.push(reason.clone());
                *final_verdict = Some(VerificationStatus::Failed {
                    reason,
                    evidence: vec![],
                });
            }
        }
        SignatureResult::NotChecked => {
            let reason = "Signature stage did not run".to_string();
            trace.push(TraceEntry {
                rule_description: reason.clone(),
                condition: "SignatureRequired".to_string(),
                matched: true,
                verdict: Some("Failed".to_string()),
            });
            if final_verdict.is_none() {
                failing_reasons.push(reason.clone());
                *final_verdict = Some(VerificationStatus::Failed {
                    reason,
                    evidence: vec![],
                });
            }
        }
    }
}

fn check_file_type_policy(
    results: &PipelineResults,
    policy: &Policy,
    trace: &mut Vec<TraceEntry>,
    final_verdict: &mut Option<VerificationStatus>,
    failing_reasons: &mut Vec<String>,
) {
    for denied in &policy.deny_file_types {
        if results.file_type.contains(denied.as_str()) {
            let reason = format!(
                "File type '{}' denied by policy (matches '{}')",
                results.file_type, denied
            );
            trace.push(TraceEntry {
                rule_description: reason.clone(),
                condition: "DeniedFileType".to_string(),
                matched: true,
                verdict: Some("Failed".to_string()),
            });
            if final_verdict.is_none() {
                failing_reasons.push(reason.clone());
                *final_verdict = Some(VerificationStatus::Failed {
                    reason,
                    evidence: vec![],
                });
            }
            return;
        }
    }
}

fn check_executable_policy(
    results: &PipelineResults,
    policy: &Policy,
    trace: &mut Vec<TraceEntry>,
    final_verdict: &mut Option<VerificationStatus>,
    failing_reasons: &mut Vec<String>,
) {
    use crate::config::ExecutableHandling;

    if !results.inspection.is_executable && !results.inspection.is_script {
        return; // not an executable; policy doesn't apply
    }

    match policy.executable_handling {
        ExecutableHandling::Allow => {
            trace.push(TraceEntry {
                rule_description: "Executable allowed by policy".to_string(),
                condition: "ExecutableHandling".to_string(),
                matched: true,
                verdict: None,
            });
        }
        ExecutableHandling::DenyAll => {
            let reason = format!(
                "Executable type '{}' denied by policy (executable_handling=deny_all)",
                results.file_type
            );
            trace.push(TraceEntry {
                rule_description: reason.clone(),
                condition: "ExecutableHandling".to_string(),
                matched: true,
                verdict: Some("Failed".to_string()),
            });
            if final_verdict.is_none() {
                failing_reasons.push(reason.clone());
                *final_verdict = Some(VerificationStatus::Failed {
                    reason,
                    evidence: vec![],
                });
            }
        }
        ExecutableHandling::BlockUnsigned => {
            // Block unsigned executables only.
            let is_signed = matches!(results.signature_status, SignatureResult::Verified { .. });
            if !is_signed {
                let reason = format!(
                    "Unsigned executable '{}' blocked by policy (executable_handling=block_unsigned)",
                    results.file_type
                );
                trace.push(TraceEntry {
                    rule_description: reason.clone(),
                    condition: "ExecutableHandling".to_string(),
                    matched: true,
                    verdict: Some("Failed".to_string()),
                });
                if final_verdict.is_none() {
                    failing_reasons.push(reason.clone());
                    *final_verdict = Some(VerificationStatus::Failed {
                        reason,
                        evidence: vec![],
                    });
                }
            } else {
                trace.push(TraceEntry {
                    rule_description: "Signed executable allowed (block_unsigned policy)"
                        .to_string(),
                    condition: "ExecutableHandling".to_string(),
                    matched: true,
                    verdict: None,
                });
            }
        }
    }
}

fn check_malware_availability_policy(
    results: &PipelineResults,
    policy: &Policy,
    trace: &mut Vec<TraceEntry>,
    final_verdict: &mut Option<VerificationStatus>,
) {
    if !policy.malware_scan_required {
        return;
    }
    let is_unavailable = matches!(
        results.malware_status,
        MalwareResult::ToolMissing { .. }
            | MalwareResult::ScanError { .. }
            | MalwareResult::NotChecked
    );
    if is_unavailable {
        let reason = "Malware scan required by policy but scanner unavailable".to_string();
        trace.push(TraceEntry {
            rule_description: reason.clone(),
            condition: "MalwareScanRequired".to_string(),
            matched: true,
            verdict: Some(
                if policy.malware_failure_is_fatal {
                    "Failed"
                } else {
                    "Unverified"
                }
                .to_string(),
            ),
        });
        if final_verdict.is_none() {
            *final_verdict = Some(if policy.malware_failure_is_fatal {
                VerificationStatus::Failed {
                    reason,
                    evidence: vec![],
                }
            } else {
                VerificationStatus::Unverified {
                    reason,
                    evidence: vec![],
                }
            });
        }
    }
}

fn check_reputation_availability_policy(
    results: &PipelineResults,
    policy: &Policy,
    trace: &mut Vec<TraceEntry>,
    final_verdict: &mut Option<VerificationStatus>,
) {
    if !policy.reputation_required {
        return;
    }
    let is_unavailable = matches!(
        results.reputation,
        ReputationResult::Unknown { .. }
            | ReputationResult::Unavailable { .. }
            | ReputationResult::ApiKeyMissing
            | ReputationResult::NotChecked
    );
    if is_unavailable {
        let reason = "Reputation check required by policy but result unavailable".to_string();
        trace.push(TraceEntry {
            rule_description: reason.clone(),
            condition: "ReputationRequired".to_string(),
            matched: true,
            verdict: Some(
                if policy.reputation_failure_is_fatal {
                    "Failed"
                } else {
                    "Unverified"
                }
                .to_string(),
            ),
        });
        if final_verdict.is_none() {
            *final_verdict = Some(if policy.reputation_failure_is_fatal {
                VerificationStatus::Failed {
                    reason,
                    evidence: vec![],
                }
            } else {
                VerificationStatus::Unverified {
                    reason,
                    evidence: vec![],
                }
            });
        }
    }
}

fn check_sbom_policy(
    _results: &PipelineResults,
    policy: &Policy,
    trace: &mut Vec<TraceEntry>,
    final_verdict: &mut Option<VerificationStatus>,
) {
    if !policy.require_sbom {
        return;
    }
    // Phase II hook: SBOM enforcement is not yet fully implemented.
    // Currently produces UNVERIFIED when require_sbom=true.
    let reason =
        "SBOM required by policy but SBOM verification is Phase II (not yet enforced)".to_string();
    trace.push(TraceEntry {
        rule_description: reason.clone(),
        condition: "SbomRequired".to_string(),
        matched: true,
        verdict: Some("Unverified".to_string()),
    });
    if final_verdict.is_none() {
        *final_verdict = Some(VerificationStatus::Unverified {
            reason,
            evidence: vec![],
        });
    }
}

fn build_evidence(
    policy: &Policy,
    trace: &[TraceEntry],
    status: &VerificationStatus,
) -> EvidenceItem {
    let mut inputs = HashMap::new();
    inputs.insert("policy_name".to_string(), policy.name.clone());
    inputs.insert("policy_version".to_string(), policy.version.clone());
    inputs.insert("policy_digest".to_string(), policy.digest());

    let mut outputs = HashMap::new();
    outputs.insert(
        "verdict".to_string(),
        serde_json::Value::String(status.label().to_string()),
    );
    outputs.insert(
        "rules_evaluated".to_string(),
        serde_json::Value::Number(serde_json::Number::from(trace.len() as u64)),
    );
    outputs.insert(
        "decision_trace".to_string(),
        serde_json::to_value(trace).unwrap_or(serde_json::Value::Null),
    );

    EvidenceItem::new("policy", inputs, outputs, HashMap::new())
}
