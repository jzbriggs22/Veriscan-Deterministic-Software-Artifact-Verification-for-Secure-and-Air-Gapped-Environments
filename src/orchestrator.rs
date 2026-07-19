/// Pipeline orchestrator: enforces stage order, tracks artifact integrity.
///
/// The orchestrator is the sole authority on stage sequencing. No CLI flag
/// can skip, reorder, or short-circuit a stage. Stages may return
/// UNVERIFIED (tool unavailable, optional check skipped) but never silently
/// pass a required check.
///
/// Artifact hash is recorded before and after each stage. Any mutation
/// detected between stages is an immediate FAILED — the pipeline halts.
use crate::config::{Policy, RunConfig};
use crate::error::VeriError;
use crate::evidence::{EvidenceItem, PipelineResults, VerificationStatus};
use crate::report::{self, JsonReport};
use crate::stages::{acquire, hash, inspect, malware, policy as policy_stage, reputation, signature};
use crate::util::fs::sha256_file;
use chrono::Utc;
use tracing::{error, info};
use uuid::Uuid;

/// Run the complete verification pipeline for a non-bundle artifact.
///
/// Returns the final JSON report (which includes the verdict).
pub async fn run_pipeline(source: &str, config: &RunConfig) -> Result<JsonReport, VeriError> {
    let run_id = Uuid::new_v4().to_string();
    let start_time = Utc::now();
    let policy = &config.policy;

    info!(
        run_id = %run_id,
        source = source,
        policy = %policy.name,
        "Verification pipeline started"
    );

    let mut all_evidence: Vec<EvidenceItem> = Vec::new();
    let mut pipeline_results = PipelineResults::default();
    let warnings: Vec<String> = Vec::new();

    // ── Stage 1: Acquire ────────────────────────────────────────────────────
    let acquire_result = match acquire::run(source, policy).await {
        Ok(r) => r,
        Err(e) => {
            error!(stage = "acquire", error = %e, "Acquire stage failed");
            return Err(e);
        }
    };
    all_evidence.extend(acquire_result.evidence.clone());
    let artifact_path = acquire_result.local_path.clone();
    let initial_sha256 = acquire_result.sha256_at_acquire.clone();
    pipeline_results.artifact_filename = acquire_result.filename.clone();
    pipeline_results.artifact_size_bytes = acquire_result.size_bytes;

    info!(
        run_id = %run_id,
        stage = "acquire",
        "Stage complete"
    );

    // ── Stage 2: Hash ───────────────────────────────────────────────────────
    let hash_result = match hash::run(
        &artifact_path,
        policy,
        config.expected_sha256.as_deref(),
        config.expected_sha512.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(stage = "hash", error = %e, "Hash stage failed");
            // Hash mismatch is a definitive FAILED.
            return build_failed_report(
                &run_id,
                &start_time,
                source,
                &acquire_result.filename,
                acquire_result.size_bytes,
                &pipeline_results,
                e.to_string(),
                all_evidence,
                policy,
                warnings,
            );
        }
    };
    pipeline_results.hash_sha256 = Some(hash_result.sha256.clone());
    pipeline_results.hash_sha512 = Some(hash_result.sha512.clone());
    pipeline_results.expected_sha256_matched = hash_result.expected_sha256_matched;
    pipeline_results.expected_sha512_matched = hash_result.expected_sha512_matched;
    all_evidence.extend(hash_result.evidence);

    // Verify artifact has not been mutated since acquire.
    assert_no_mutation(&artifact_path, &initial_sha256)?;

    info!(run_id = %run_id, stage = "hash", "Stage complete");

    // ── Stage 3: Signature ──────────────────────────────────────────────────
    let sig_result = signature::run(
        &artifact_path,
        policy,
        config.detached_sig_path.as_deref(),
        config.trusted_keys_dir.as_deref(),
    )
    .await?;
    pipeline_results.signature_status = sig_result.result;
    all_evidence.extend(sig_result.evidence);
    assert_no_mutation(&artifact_path, &initial_sha256)?;

    info!(run_id = %run_id, stage = "signature", "Stage complete");

    // ── Stage 4: Malware scan ───────────────────────────────────────────────
    let malware_result = malware::run(&artifact_path, policy).await?;
    pipeline_results.malware_status = malware_result.result;
    all_evidence.extend(malware_result.evidence);
    assert_no_mutation(&artifact_path, &initial_sha256)?;

    info!(run_id = %run_id, stage = "malware", "Stage complete");

    // ── Stage 5: Static inspection ──────────────────────────────────────────
    let inspect_result = inspect::run(&artifact_path, policy).await?;
    pipeline_results.inspection = inspect_result.result;
    pipeline_results.file_type = pipeline_results.inspection.file_type.clone();
    all_evidence.extend(inspect_result.evidence);
    assert_no_mutation(&artifact_path, &initial_sha256)?;

    info!(run_id = %run_id, stage = "inspect", "Stage complete");

    // ── Stage 6: Reputation ─────────────────────────────────────────────────
    let sha256_for_vt = pipeline_results.hash_sha256.clone().unwrap_or_default();
    let rep_result = reputation::run(&sha256_for_vt, policy, config.offline_mode).await?;
    pipeline_results.reputation = rep_result.result;
    all_evidence.extend(rep_result.evidence);

    info!(run_id = %run_id, stage = "reputation", "Stage complete");

    // ── Stage 7: Policy evaluation ──────────────────────────────────────────
    let policy_result = policy_stage::evaluate(&pipeline_results, policy)?;
    all_evidence.extend(policy_result.evidence);

    info!(
        run_id = %run_id,
        stage = "policy",
        verdict = %policy_result.status.label(),
        "Pipeline complete"
    );

    // ── Build report ────────────────────────────────────────────────────────
    let json_report = report::build_json_report(
        &run_id,
        &start_time,
        source,
        &acquire_result.filename,
        acquire_result.size_bytes,
        &pipeline_results,
        &policy_result.status,
        policy_result.decision_trace,
        all_evidence,
        policy,
        warnings,
    );

    Ok(json_report)
}

/// Run the verification pipeline for an offline bundle directory.
pub async fn run_bundle_pipeline(
    bundle_dir: &std::path::Path,
    config: &RunConfig,
) -> Result<JsonReport, VeriError> {
    use crate::stages::bundle;

    let run_id = Uuid::new_v4().to_string();

    info!(
        run_id = %run_id,
        bundle = %bundle_dir.display(),
        "Bundle verification pipeline started"
    );

    // Step 1: Verify bundle integrity (manifest signature + file hashes).
    let artifact_path = bundle::verify(bundle_dir).await.map_err(|e| {
        error!(error = %e, "Bundle verification failed");
        e
    })?;

    info!(
        artifact_path = %artifact_path.display(),
        "Bundle integrity verified; proceeding with artifact verification"
    );

    // Step 2: Run normal pipeline on the verified artifact.
    // In offline mode, network-dependent stages skip gracefully.
    let source = artifact_path.display().to_string();

    // Override config for offline mode.
    let offline_config = RunConfig {
        offline_mode: true,
        trusted_keys_dir: Some(bundle_dir.join("trusted_keys")),
        // Bundle creation appends ".sig" to the full artifact filename
        // (e.g. `artifact.tar.gz.sig`), so look it up the same way rather
        // than replacing the last extension.
        detached_sig_path: Some(std::path::PathBuf::from(format!(
            "{}.sig",
            artifact_path.display()
        ))),
        ..config.clone()
    };

    run_pipeline(&source, &offline_config).await
}

/// Assert the artifact has not been modified since `expected_sha256`.
fn assert_no_mutation(artifact_path: &std::path::Path, expected_sha256: &str) -> Result<(), VeriError> {
    let current = sha256_file(artifact_path)?;
    if current != expected_sha256 {
        return Err(VeriError::ArtifactMutated {
            before: expected_sha256.to_string(),
            after: current,
        });
    }
    Ok(())
}

/// Construct a FAILED report for early pipeline errors.
#[allow(clippy::too_many_arguments)]
fn build_failed_report(
    run_id: &str,
    start_time: &chrono::DateTime<Utc>,
    source: &str,
    filename: &str,
    size_bytes: u64,
    pipeline_results: &PipelineResults,
    reason: String,
    evidence: Vec<EvidenceItem>,
    policy: &Policy,
    warnings: Vec<String>,
) -> Result<JsonReport, VeriError> {
    let status = VerificationStatus::Failed {
        reason: reason.clone(),
        evidence: vec![],
    };
    let report = report::build_json_report(
        run_id,
        start_time,
        source,
        filename,
        size_bytes,
        pipeline_results,
        &status,
        vec![],
        evidence,
        policy,
        warnings,
    );
    Ok(report)
}
