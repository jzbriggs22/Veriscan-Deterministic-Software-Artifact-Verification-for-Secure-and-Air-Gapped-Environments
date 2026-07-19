/// Integration tests: JSON report schema stability.
///
/// Verifies that:
/// - The report serialises to valid JSON.
/// - All required fields are present.
/// - Verdict status values are bounded to known values.
/// - Evidence items have required fields.
/// - Deterministic IDs are 64-char hex strings.
use chrono::Utc;
use veriscan_lib::{
    config::Policy,
    evidence::{
        EvidenceItem, InspectionResult, MalwareResult, PipelineResults, ReputationResult,
        SignatureResult, VerificationStatus,
    },
    report::{build_json_report, render_markdown, JsonReport},
    stages::policy::TraceEntry,
};
use std::collections::HashMap;

fn default_policy() -> Policy {
    Policy::default_policy().expect("default policy")
}

fn sample_pipeline() -> PipelineResults {
    let mut p = PipelineResults::default();
    p.hash_sha256 = Some("a".repeat(64));
    p.hash_sha512 = Some("b".repeat(128));
    p.expected_sha256_matched = Some(true);
    p.signature_status = SignatureResult::Verified {
        signer_uid: "Test User <test@example.com>".to_string(),
        fingerprint: "AABBCCDD11223344AABBCCDD11223344AABBCCDD".to_string(),
    };
    p.malware_status = MalwareResult::Clean {
        engine: "ClamAV".to_string(),
        version: "0.104.0".to_string(),
    };
    p.reputation = ReputationResult::Clean {
        engines_total: 72,
        engines_detected: 0,
        source: "VirusTotal".to_string(),
        last_seen: Some("2024-01-01T00:00:00Z".to_string()),
        link: None,
    };
    p.inspection = InspectionResult {
        file_type: "PDF".to_string(),
        entropy: 4.2,
        entropy_flagged: false,
        indicators: vec![],
        strings_excerpt: vec!["sample string".to_string()],
        is_executable: false,
        is_script: false,
    };
    p.file_type = "PDF".to_string();
    p.artifact_filename = "test_artifact.pdf".to_string();
    p.artifact_size_bytes = 1234;
    p
}

fn sample_trace() -> Vec<TraceEntry> {
    vec![
        TraceEntry {
            rule_description: "Malware not detected".to_string(),
            condition: "MalwareDetected".to_string(),
            matched: false,
            verdict: None,
        },
        TraceEntry {
            rule_description: "Signature verified".to_string(),
            condition: "SignatureRequired".to_string(),
            matched: true,
            verdict: Some("Verified".to_string()),
        },
    ]
}

fn sample_evidence() -> Vec<EvidenceItem> {
    let mut inputs = HashMap::new();
    inputs.insert("artifact_path".to_string(), "/tmp/test.bin".to_string());
    let mut outputs = HashMap::new();
    outputs.insert("sha256".to_string(), serde_json::json!("a".repeat(64)));
    vec![
        EvidenceItem::new("hash", inputs, outputs, HashMap::new()),
    ]
}

fn build_test_report(status: VerificationStatus) -> JsonReport {
    let policy = default_policy();
    let pipeline = sample_pipeline();
    build_json_report(
        "test-run-id-123",
        &Utc::now(),
        "/tmp/test_artifact.pdf",
        "test_artifact.pdf",
        1234,
        &pipeline,
        &status,
        sample_trace(),
        sample_evidence(),
        &policy,
        vec!["test warning".to_string()],
    )
}

#[test]
fn test_report_serialises_to_valid_json() {
    let report = build_test_report(VerificationStatus::Verified);
    let json_str = serde_json::to_string_pretty(&report).expect("serialise");
    assert!(!json_str.is_empty(), "JSON output must not be empty");

    // Parse back to Value to verify valid JSON.
    let value: serde_json::Value = serde_json::from_str(&json_str).expect("parse back");
    assert!(value.is_object(), "Report must be a JSON object");
}

#[test]
fn test_report_required_fields_present() {
    let report = build_test_report(VerificationStatus::Verified);
    let json_str = serde_json::to_string_pretty(&report).expect("serialise");
    let value: serde_json::Value = serde_json::from_str(&json_str).expect("parse");

    let required_fields = [
        "schema_version",
        "run_id",
        "timestamp",
        "elapsed_secs",
        "artifact",
        "verdict",
        "hashes",
        "signature",
        "malware_scan",
        "reputation",
        "inspection",
        "policy",
        "decision_trace",
        "evidence",
        "tool_versions",
        "warnings",
    ];
    for field in &required_fields {
        assert!(
            value.get(field).is_some(),
            "Required field '{}' missing from report",
            field
        );
    }
}

#[test]
fn test_report_schema_version_is_stable() {
    let report = build_test_report(VerificationStatus::Verified);
    assert_eq!(report.schema_version, "1.0", "Schema version must be 1.0");
}

#[test]
fn test_report_verdict_values_are_known() {
    let known_verdicts = ["VERIFIED", "UNVERIFIED", "FAILED"];

    let verified = build_test_report(VerificationStatus::Verified);
    assert!(
        known_verdicts.contains(&verified.verdict.status.as_str()),
        "Verdict '{}' is not a known status",
        verified.verdict.status
    );

    let unverified = build_test_report(VerificationStatus::Unverified {
        reason: "test".to_string(),
        evidence: vec![],
    });
    assert_eq!(unverified.verdict.status, "UNVERIFIED");

    let failed = build_test_report(VerificationStatus::Failed {
        reason: "test".to_string(),
        evidence: vec![],
    });
    assert_eq!(failed.verdict.status, "FAILED");
}

#[test]
fn test_report_exit_codes_match_verdicts() {
    let verified = build_test_report(VerificationStatus::Verified);
    assert_eq!(verified.verdict.exit_code, 0);

    let unverified = build_test_report(VerificationStatus::Unverified {
        reason: "test".to_string(),
        evidence: vec![],
    });
    assert_eq!(unverified.verdict.exit_code, 10);

    let failed = build_test_report(VerificationStatus::Failed {
        reason: "test".to_string(),
        evidence: vec![],
    });
    assert_eq!(failed.verdict.exit_code, 20);
}

#[test]
fn test_evidence_items_have_required_fields() {
    let report = build_test_report(VerificationStatus::Verified);
    assert!(
        !report.evidence.is_empty(),
        "Report must have at least one evidence item"
    );

    for item in &report.evidence {
        assert!(!item.stage_name.is_empty(), "Evidence must have stage_name");
        assert!(!item.timestamp.is_empty(), "Evidence must have timestamp");
        assert!(
            !item.deterministic_id.is_empty(),
            "Evidence must have deterministic_id"
        );
        assert_eq!(
            item.deterministic_id.len(),
            64,
            "Deterministic ID must be 64 hex chars"
        );
        // Verify ID contains only hex chars.
        assert!(
            item.deterministic_id.chars().all(|c| c.is_ascii_hexdigit()),
            "Deterministic ID must be hex"
        );
    }
}

#[test]
fn test_decision_trace_is_serialisable() {
    let report = build_test_report(VerificationStatus::Verified);
    let json_str = serde_json::to_string_pretty(&report).expect("serialise");
    let value: serde_json::Value = serde_json::from_str(&json_str).expect("parse");

    let trace = value
        .get("decision_trace")
        .expect("decision_trace field")
        .as_array()
        .expect("decision_trace must be array");

    assert!(!trace.is_empty(), "Decision trace must not be empty");
    for entry in trace {
        assert!(
            entry.get("rule_description").is_some(),
            "Trace entry must have rule_description"
        );
        assert!(
            entry.get("condition").is_some(),
            "Trace entry must have condition"
        );
        assert!(
            entry.get("matched").is_some(),
            "Trace entry must have matched"
        );
    }
}

#[test]
fn test_markdown_report_rendered_without_panic() {
    let report = build_test_report(VerificationStatus::Verified);
    let md = render_markdown(&report);
    assert!(!md.is_empty(), "Markdown report must not be empty");
    assert!(md.contains("VERIFIED"), "Markdown must contain verdict");
    assert!(md.contains("SHA-256"), "Markdown must mention SHA-256");
    assert!(md.contains("Signature"), "Markdown must mention Signature");
    assert!(md.contains("Decision Trace"), "Markdown must contain decision trace");
}

#[test]
fn test_markdown_for_failed_report_shows_reason() {
    let reason = "Test failure reason for report";
    let report = build_test_report(VerificationStatus::Failed {
        reason: reason.to_string(),
        evidence: vec![],
    });
    let md = render_markdown(&report);
    assert!(md.contains(reason), "Markdown must include failure reason");
    assert!(md.contains("FAILED"), "Markdown must show FAILED verdict");
}

#[test]
fn test_report_policy_digest_consistent() {
    let r1 = build_test_report(VerificationStatus::Verified);
    let r2 = build_test_report(VerificationStatus::Verified);
    assert_eq!(
        r1.policy.digest, r2.policy.digest,
        "Policy digest must be deterministic"
    );
    assert_eq!(r1.policy.digest.len(), 64, "Policy digest must be 64-char hex");
}

#[test]
fn test_report_roundtrip_preserves_all_fields() {
    let report = build_test_report(VerificationStatus::Verified);

    // Serialise then deserialise.
    let json = serde_json::to_string_pretty(&report).expect("serialise");
    let restored: JsonReport = serde_json::from_str(&json).expect("deserialise");

    assert_eq!(restored.schema_version, report.schema_version);
    assert_eq!(restored.run_id, report.run_id);
    assert_eq!(restored.verdict.status, report.verdict.status);
    assert_eq!(restored.verdict.exit_code, report.verdict.exit_code);
    assert_eq!(restored.policy.name, report.policy.name);
    assert_eq!(restored.evidence.len(), report.evidence.len());
    assert_eq!(restored.decision_trace.len(), report.decision_trace.len());
}

#[test]
fn test_report_hashes_present_and_correct_length() {
    let report = build_test_report(VerificationStatus::Verified);
    let sha256 = report.hashes.sha256.as_ref().expect("sha256 present");
    let sha512 = report.hashes.sha512.as_ref().expect("sha512 present");
    assert_eq!(sha256.len(), 64, "SHA-256 must be 64 hex chars");
    assert_eq!(sha512.len(), 128, "SHA-512 must be 128 hex chars");
}

#[test]
fn test_report_contains_no_sensitive_fields() {
    let report = build_test_report(VerificationStatus::Verified);
    let json = serde_json::to_string_pretty(&report).expect("serialise");

    // API keys must never appear in reports.
    assert!(!json.contains("api_key"), "API key must not appear in report JSON");
    assert!(!json.contains("VT_API_KEY"), "VT env var value must not appear in report");
    // Passwords, tokens, etc.
    assert!(!json.contains("password"), "Password must not appear in report");
    assert!(!json.contains("secret"), "Secret must not appear in report");
}

#[test]
fn test_append_audit_jsonl_accumulates_one_record_per_run() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let log_path = dir.path().join("audit.jsonl");

    let report = build_test_report(VerificationStatus::Verified);
    veriscan_lib::report::append_audit_jsonl(&report, &log_path).expect("first append");
    veriscan_lib::report::append_audit_jsonl(&report, &log_path).expect("second append");

    let contents = std::fs::read_to_string(&log_path).expect("read audit log");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 2, "one JSONL record per verification run");
    for line in lines {
        let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
        assert_eq!(parsed["verdict"]["status"], "VERIFIED");
    }
}
