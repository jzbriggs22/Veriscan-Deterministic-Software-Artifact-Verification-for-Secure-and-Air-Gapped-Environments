/// Report generation: JSON and Markdown outputs.
///
/// The JSON report is the authoritative machine-readable artifact; the
/// Markdown report is a human-readable summary for analysts and auditors.
/// Both are produced from the same data structure to prevent divergence.
use crate::config::Policy;
use crate::evidence::{
    EvidenceItem, MalwareResult, PipelineResults, ReputationResult, SignatureResult,
    VerificationStatus,
};
use crate::stages::policy::TraceEntry;
use crate::util::time::iso8601_now;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The stable JSON report schema (version 1.0).
/// All field names and types are frozen; additions are additive only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    pub schema_version: String,
    pub run_id: String,
    pub timestamp: String,
    pub elapsed_secs: f64,
    pub artifact: ArtifactInfo,
    pub verdict: VerdictInfo,
    pub hashes: HashInfo,
    pub signature: SignatureInfo,
    pub malware_scan: MalwareScanInfo,
    pub reputation: ReputationInfo,
    pub inspection: InspectionInfo,
    pub policy: PolicyInfo,
    pub decision_trace: Vec<TraceEntry>,
    pub evidence: Vec<EvidenceItem>,
    pub tool_versions: std::collections::HashMap<String, String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub source: String,
    pub filename: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictInfo {
    pub status: String,
    pub reason: Option<String>,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashInfo {
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub sha256_verified: Option<bool>,
    pub sha512_verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub status: String,
    pub signer_uid: Option<String>,
    pub fingerprint: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareScanInfo {
    pub status: String,
    pub engine: Option<String>,
    pub engine_version: Option<String>,
    pub detections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationInfo {
    pub status: String,
    pub engines_total: Option<u32>,
    pub engines_detected: Option<u32>,
    pub source: Option<String>,
    pub last_seen: Option<String>,
    pub link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionInfo {
    pub file_type: String,
    pub entropy: f64,
    pub entropy_flagged: bool,
    pub indicators: Vec<String>,
    pub is_executable: bool,
    pub is_script: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub name: String,
    pub version: String,
    pub digest: String,
}

/// Build the complete JSON report from pipeline results.
#[allow(clippy::too_many_arguments)]
pub fn build_json_report(
    run_id: &str,
    start_time: &chrono::DateTime<chrono::Utc>,
    source: &str,
    filename: &str,
    size_bytes: u64,
    pipeline: &PipelineResults,
    status: &VerificationStatus,
    decision_trace: Vec<TraceEntry>,
    all_evidence: Vec<EvidenceItem>,
    policy: &Policy,
    warnings: Vec<String>,
) -> JsonReport {
    let elapsed_secs = (chrono::Utc::now() - *start_time).num_milliseconds() as f64 / 1000.0;

    let verdict_reason = match status {
        VerificationStatus::Verified => None,
        VerificationStatus::Unverified { reason, .. } => Some(reason.clone()),
        VerificationStatus::Failed { reason, .. } => Some(reason.clone()),
    };

    let signature_info = match &pipeline.signature_status {
        SignatureResult::NotChecked => SignatureInfo {
            status: "not_checked".to_string(),
            signer_uid: None,
            fingerprint: None,
            detail: None,
        },
        SignatureResult::Verified { signer_uid, fingerprint } => SignatureInfo {
            status: "verified".to_string(),
            signer_uid: Some(signer_uid.clone()),
            fingerprint: Some(fingerprint.clone()),
            detail: None,
        },
        SignatureResult::Missing => SignatureInfo {
            status: "missing".to_string(),
            signer_uid: None,
            fingerprint: None,
            detail: Some("No signature file found".to_string()),
        },
        SignatureResult::Invalid { reason } => SignatureInfo {
            status: "invalid".to_string(),
            signer_uid: None,
            fingerprint: None,
            detail: Some(reason.clone()),
        },
        SignatureResult::SignerNotAllowed { fingerprint } => SignatureInfo {
            status: "signer_not_allowed".to_string(),
            signer_uid: None,
            fingerprint: Some(fingerprint.clone()),
            detail: Some("Fingerprint not in allow list".to_string()),
        },
    };

    let malware_info = match &pipeline.malware_status {
        MalwareResult::NotChecked => MalwareScanInfo {
            status: "not_checked".to_string(),
            engine: None,
            engine_version: None,
            detections: vec![],
        },
        MalwareResult::Clean { engine, version } => MalwareScanInfo {
            status: "clean".to_string(),
            engine: Some(engine.clone()),
            engine_version: Some(version.clone()),
            detections: vec![],
        },
        MalwareResult::Detected { engine, version, detections } => MalwareScanInfo {
            status: "detected".to_string(),
            engine: Some(engine.clone()),
            engine_version: Some(version.clone()),
            detections: detections.clone(),
        },
        MalwareResult::ToolMissing { tool_path } => MalwareScanInfo {
            status: "tool_missing".to_string(),
            engine: Some(tool_path.clone()),
            engine_version: None,
            detections: vec![],
        },
        MalwareResult::ScanError { reason } => MalwareScanInfo {
            status: "scan_error".to_string(),
            engine: None,
            engine_version: None,
            detections: vec![serde_json::to_string(reason).unwrap_or_default()],
        },
    };

    let reputation_info = match &pipeline.reputation {
        ReputationResult::NotChecked => ReputationInfo {
            status: "not_checked".to_string(),
            engines_total: None,
            engines_detected: None,
            source: None,
            last_seen: None,
            link: None,
        },
        ReputationResult::Clean { engines_total, engines_detected, source, last_seen, link } => {
            ReputationInfo {
                status: "clean".to_string(),
                engines_total: Some(*engines_total),
                engines_detected: Some(*engines_detected),
                source: Some(source.clone()),
                last_seen: last_seen.clone(),
                link: link.clone(),
            }
        }
        ReputationResult::Malicious { engines_total, engines_detected, source, last_seen, link } => {
            ReputationInfo {
                status: "malicious".to_string(),
                engines_total: Some(*engines_total),
                engines_detected: Some(*engines_detected),
                source: Some(source.clone()),
                last_seen: last_seen.clone(),
                link: link.clone(),
            }
        }
        ReputationResult::Unknown { reason } => ReputationInfo {
            status: "unknown".to_string(),
            engines_total: None,
            engines_detected: None,
            source: None,
            last_seen: None,
            link: Some(reason.clone()),
        },
        ReputationResult::ApiKeyMissing => ReputationInfo {
            status: "api_key_missing".to_string(),
            engines_total: None,
            engines_detected: None,
            source: None,
            last_seen: None,
            link: None,
        },
        ReputationResult::Unavailable { reason } => ReputationInfo {
            status: "unavailable".to_string(),
            engines_total: None,
            engines_detected: None,
            source: None,
            last_seen: None,
            link: Some(reason.clone()),
        },
    };

    JsonReport {
        schema_version: "1.0".to_string(),
        run_id: run_id.to_string(),
        timestamp: iso8601_now(),
        elapsed_secs,
        artifact: ArtifactInfo {
            source: source.to_string(),
            filename: filename.to_string(),
            size_bytes,
        },
        verdict: VerdictInfo {
            status: status.label().to_string(),
            reason: verdict_reason,
            exit_code: status.exit_code(),
        },
        hashes: HashInfo {
            sha256: pipeline.hash_sha256.clone(),
            sha512: pipeline.hash_sha512.clone(),
            sha256_verified: pipeline.expected_sha256_matched,
            sha512_verified: pipeline.expected_sha512_matched,
        },
        signature: signature_info,
        malware_scan: malware_info,
        reputation: reputation_info,
        inspection: InspectionInfo {
            file_type: pipeline.inspection.file_type.clone(),
            entropy: pipeline.inspection.entropy,
            entropy_flagged: pipeline.inspection.entropy_flagged,
            indicators: pipeline.inspection.indicators.clone(),
            is_executable: pipeline.inspection.is_executable,
            is_script: pipeline.inspection.is_script,
        },
        policy: PolicyInfo {
            name: policy.name.clone(),
            version: policy.version.clone(),
            digest: policy.digest(),
        },
        decision_trace,
        evidence: all_evidence,
        tool_versions: std::collections::HashMap::new(),
        warnings,
    }
}

/// Render a JSON report to a Markdown summary.
pub fn render_markdown(report: &JsonReport) -> String {
    let mut md = String::new();

    let verdict_emoji = match report.verdict.status.as_str() {
        "VERIFIED" => "✅",
        "UNVERIFIED" => "⚠️",
        "FAILED" => "❌",
        _ => "❓",
    };

    md.push_str(&format!(
        "# Veriscan Verification Report\n\n\
         **Verdict:** {} `{}`\n\n\
         **Run ID:** `{}`  \n\
         **Timestamp:** {}  \n\
         **Elapsed:** {:.2}s  \n\
         **Policy:** {} v{}  \n\
         **Policy Digest:** `{}`\n\n",
        verdict_emoji,
        report.verdict.status,
        report.run_id,
        report.timestamp,
        report.elapsed_secs,
        report.policy.name,
        report.policy.version,
        report.policy.digest,
    ));

    if let Some(reason) = &report.verdict.reason {
        md.push_str(&format!("**Verdict Reason:** {}\n\n", reason));
    }

    md.push_str("---\n\n");

    // Artifact info.
    md.push_str("## Artifact\n\n");
    md.push_str("| Field | Value |\n|---|---|\n");
    md.push_str(&format!("| Source | `{}` |\n", report.artifact.source));
    md.push_str(&format!("| Filename | `{}` |\n", report.artifact.filename));
    md.push_str(&format!("| Size | {} bytes |\n", report.artifact.size_bytes));
    md.push_str(&format!(
        "| File Type | {} |\n",
        report.inspection.file_type
    ));
    md.push('\n');

    // Hashes.
    md.push_str("## Cryptographic Hashes\n\n");
    md.push_str("| Algorithm | Digest | Verified |\n|---|---|---|\n");
    if let Some(sha256) = &report.hashes.sha256 {
        let v = report
            .hashes
            .sha256_verified
            .map(|b| if b { "Yes" } else { "MISMATCH" })
            .unwrap_or("Not checked");
        md.push_str(&format!("| SHA-256 | `{}` | {} |\n", sha256, v));
    }
    if let Some(sha512) = &report.hashes.sha512 {
        let v = report
            .hashes
            .sha512_verified
            .map(|b| if b { "Yes" } else { "MISMATCH" })
            .unwrap_or("Not checked");
        md.push_str(&format!("| SHA-512 | `{}...` | {} |\n", &sha512[..16], v));
    }
    md.push('\n');

    // Signature.
    md.push_str("## PGP Signature\n\n");
    md.push_str(&format!(
        "**Status:** `{}`\n\n",
        report.signature.status
    ));
    if let Some(uid) = &report.signature.signer_uid {
        md.push_str(&format!("**Signer:** {}\n\n", uid));
    }
    if let Some(fp) = &report.signature.fingerprint {
        md.push_str(&format!("**Fingerprint:** `{}`\n\n", fp));
    }
    if let Some(detail) = &report.signature.detail {
        md.push_str(&format!("**Detail:** {}\n\n", detail));
    }

    // Malware.
    md.push_str("## Malware Scan\n\n");
    md.push_str(&format!(
        "**Status:** `{}`",
        report.malware_scan.status
    ));
    if let Some(engine) = &report.malware_scan.engine {
        md.push_str(&format!("  **Engine:** {}", engine));
    }
    if let Some(ver) = &report.malware_scan.engine_version {
        md.push_str(&format!(" `{}`", ver));
    }
    md.push_str("\n\n");
    if !report.malware_scan.detections.is_empty() {
        md.push_str("**Detections:**\n");
        for d in &report.malware_scan.detections {
            md.push_str(&format!("- `{}`\n", d));
        }
        md.push('\n');
    }

    // Reputation.
    md.push_str("## Reputation\n\n");
    md.push_str(&format!("**Status:** `{}`", report.reputation.status));
    if let (Some(total), Some(detected)) =
        (report.reputation.engines_total, report.reputation.engines_detected)
    {
        md.push_str(&format!("  **Engines:** {}/{} detected", detected, total));
    }
    if let Some(source) = &report.reputation.source {
        md.push_str(&format!("  **Source:** {}", source));
    }
    md.push_str("\n\n");

    // Inspection.
    md.push_str("## Static Inspection\n\n");
    md.push_str(&format!(
        "| Property | Value |\n|---|---|\n\
         | File Type | {} |\n\
         | Entropy | {:.4} bits |\n\
         | Entropy Flagged | {} |\n\
         | Executable | {} |\n\
         | Script | {} |\n\n",
        report.inspection.file_type,
        report.inspection.entropy,
        report.inspection.entropy_flagged,
        report.inspection.is_executable,
        report.inspection.is_script,
    ));

    if !report.inspection.indicators.is_empty() {
        md.push_str("**Indicators Found:**\n");
        for ind in report.inspection.indicators.iter().take(10) {
            md.push_str(&format!("- {}\n", ind));
        }
        md.push('\n');
    }

    // Decision trace.
    md.push_str("## Decision Trace\n\n");
    md.push_str("| Rule | Matched | Verdict |\n|---|---|---|\n");
    for entry in &report.decision_trace {
        let verdict = entry.verdict.as_deref().unwrap_or("-");
        md.push_str(&format!(
            "| {} | {} | {} |\n",
            entry.rule_description,
            if entry.matched { "Yes" } else { "No" },
            verdict,
        ));
    }
    md.push('\n');

    // Warnings.
    if !report.warnings.is_empty() {
        md.push_str("## Warnings\n\n");
        for w in &report.warnings {
            md.push_str(&format!("- {}\n", w));
        }
        md.push('\n');
    }

    // Evidence summary.
    md.push_str("## Evidence Summary\n\n");
    md.push_str(&format!(
        "{} evidence items collected.\n\n",
        report.evidence.len()
    ));
    md.push_str("| Stage | Timestamp | Deterministic ID |\n|---|---|---|\n");
    for e in &report.evidence {
        md.push_str(&format!(
            "| {} | {} | `{}` |\n",
            e.stage_name,
            e.timestamp,
            &e.deterministic_id[..16],
        ));
    }
    md.push_str("\n---\n\n");
    md.push_str("*Generated by veriscan. This report is evidence under the defined policy.*\n");

    md
}

/// Write a JSON report to disk.
pub fn write_json(report: &JsonReport, path: &Path) -> Result<(), crate::error::VeriError> {
    let json =
        serde_json::to_string_pretty(report).map_err(|e| crate::error::VeriError::Internal(e.to_string()))?;
    crate::util::fs::write_bytes_atomic(path, json.as_bytes())
}

/// Write a Markdown report to disk.
pub fn write_markdown(report: &JsonReport, path: &Path) -> Result<(), crate::error::VeriError> {
    let md = render_markdown(report);
    crate::util::fs::write_bytes_atomic(path, md.as_bytes())
}

/// Append the report to an audit log as a single JSON line (JSONL).
///
/// One record per verification run; the file is created if absent and never
/// truncated, so it accumulates an append-only audit trail across runs.
pub fn append_audit_jsonl(report: &JsonReport, path: &Path) -> Result<(), crate::error::VeriError> {
    use std::io::Write;

    let json = serde_json::to_string(report)
        .map_err(|e| crate::error::VeriError::Internal(e.to_string()))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| crate::error::VeriError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
    writeln!(file, "{}", json).map_err(|e| crate::error::VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })
}
