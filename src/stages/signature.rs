/// Signature verification stage using sequoia-openpgp.
///
/// Verifies PGP detached signatures over artifacts. Supports armored (.asc)
/// and binary (.sig) signature files. Signer fingerprint pinning is enforced
/// when `allow_signers` is non-empty.
///
/// Never executes the artifact; only reads its bytes for cryptographic
/// verification.
use crate::config::Policy;
use crate::error::VeriError;
use crate::evidence::{EvidenceItem, SignatureResult};
use sequoia_openpgp::{
    cert::prelude::*,
    parse::{
        stream::{
            DetachedVerifierBuilder, GoodChecksum, MessageLayer, MessageStructure,
            VerificationHelper,
        },
        Parse,
    },
    policy::StandardPolicy,
    KeyHandle,
};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};
use walkdir::WalkDir;

/// Result of the signature stage.
#[derive(Debug)]
pub struct SignatureStageResult {
    pub result: SignatureResult,
    pub evidence: Vec<EvidenceItem>,
}

/// Run the PGP signature verification stage.
///
/// Looks for the signature file at `sig_path` (if provided) or
/// `<artifact_path>.sig` / `<artifact_path>.asc`.
/// Loads trusted public keys from `trusted_keys_dir` (if provided) or
/// from the paths listed in `policy.allow_signers`.
pub async fn run(
    artifact_path: &Path,
    policy: &Policy,
    sig_path_override: Option<&Path>,
    trusted_keys_dir: Option<&Path>,
) -> Result<SignatureStageResult, VeriError> {
    info!(stage = "signature", artifact = %artifact_path.display(), "Starting signature verification");

    // Locate the signature file.
    let sig_path = match sig_path_override {
        Some(p) => {
            if !p.exists() {
                if policy.require_signature {
                    return Ok(SignatureStageResult {
                        result: SignatureResult::Missing,
                        evidence: vec![build_evidence("missing", "", "", "Signature file not found at provided path")],
                    });
                }
                return Ok(SignatureStageResult {
                    result: SignatureResult::Missing,
                    evidence: vec![build_evidence("missing", "", "", "No signature file")],
                });
            }
            p.to_path_buf()
        }
        None => {
            // Try common adjacent locations.
            let candidates = [
                artifact_path.with_extension("sig"),
                artifact_path.with_extension("asc"),
                {
                    let mut p = artifact_path.to_path_buf();
                    let name = p
                        .file_name()
                        .map(|n| format!("{}.sig", n.to_string_lossy()))
                        .unwrap_or_default();
                    p.set_file_name(name);
                    p
                },
            ];
            match candidates.iter().find(|c| c.exists()) {
                Some(p) => p.clone(),
                None => {
                    info!(stage = "signature", "No signature file found");
                    return Ok(SignatureStageResult {
                        result: SignatureResult::Missing,
                        evidence: vec![build_evidence(
                            "missing",
                            "",
                            "",
                            "No .sig or .asc file found adjacent to artifact",
                        )],
                    });
                }
            }
        }
    };

    info!(sig_path = %sig_path.display(), "Found signature file");

    // Load public keys from trusted_keys_dir or adjacent keys directory.
    let certs = load_trusted_keys(trusted_keys_dir, artifact_path)?;

    if certs.is_empty() {
        warn!(stage = "signature", "No trusted public keys loaded; cannot verify");
        return Ok(SignatureStageResult {
            result: SignatureResult::Invalid {
                reason: "No trusted public keys available for verification".to_string(),
            },
            evidence: vec![build_evidence(
                "invalid",
                &sig_path.display().to_string(),
                "",
                "No trusted keys loaded",
            )],
        });
    }

    // Read artifact and signature bytes.
    let artifact_bytes = std::fs::read(artifact_path).map_err(|e| VeriError::Io {
        path: artifact_path.display().to_string(),
        source: e,
    })?;
    let sig_bytes = std::fs::read(&sig_path).map_err(|e| VeriError::Io {
        path: sig_path.display().to_string(),
        source: e,
    })?;

    // Perform verification.
    match verify_detached(&artifact_bytes, &sig_bytes, &certs) {
        Ok((fingerprint, uid)) => {
            // Fingerprint pinning check.
            if !policy.allow_signers.is_empty() {
                let fp_clean = fingerprint.replace(' ', "").to_lowercase();
                let allowed = policy
                    .allow_signers
                    .iter()
                    .any(|a| a.replace(' ', "").to_lowercase() == fp_clean);
                if !allowed {
                    warn!(fingerprint = %fingerprint, "Signer not in allow list");
                    return Ok(SignatureStageResult {
                        result: SignatureResult::SignerNotAllowed {
                            fingerprint: fingerprint.clone(),
                        },
                        evidence: vec![build_evidence(
                            "signer_not_allowed",
                            &sig_path.display().to_string(),
                            &fingerprint,
                            &format!("Fingerprint '{}' not in allow_signers", fingerprint),
                        )],
                    });
                }
            }

            info!(fingerprint = %fingerprint, uid = %uid, "Signature verified");
            Ok(SignatureStageResult {
                result: SignatureResult::Verified {
                    signer_uid: uid.clone(),
                    fingerprint: fingerprint.clone(),
                },
                evidence: vec![build_evidence_verified(
                    &sig_path.display().to_string(),
                    &fingerprint,
                    &uid,
                )],
            })
        }
        Err(e) => {
            warn!(error = %e, "Signature verification failed");
            Ok(SignatureStageResult {
                result: SignatureResult::Invalid {
                    reason: e.to_string(),
                },
                evidence: vec![build_evidence(
                    "invalid",
                    &sig_path.display().to_string(),
                    "",
                    &e.to_string(),
                )],
            })
        }
    }
}

/// Sequoia verification helper that accumulates signer information.
struct SigHelper {
    certs: Vec<CertPublic>,
    verified_fp: Option<String>,
    verified_uid: Option<String>,
    verification_error: Option<String>,
}

// We need to hold Cert in a way that implements VerificationHelper.
// Sequoia's Cert is not Clone, so we box it.
type CertPublic = sequoia_openpgp::Cert;

impl VerificationHelper for SigHelper {
    fn get_certs(
        &mut self,
        ids: &[KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        let matching: Vec<sequoia_openpgp::Cert> = self
            .certs
            .iter()
            .filter(|cert| {
                ids.iter()
                    .any(|id| cert.keys().any(|k| k.key_handle().aliases(id)))
            })
            .cloned()
            .collect();
        Ok(matching)
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        let mut found_good = false;
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    match result {
                        Ok(GoodChecksum { ka, .. }) => {
                            found_good = true;
                            let fp = ka.key().fingerprint().to_hex();
                            let uid = ka
                                .cert()
                                .userids()
                                .next()
                                .map(|u| String::from_utf8_lossy(u.value()).to_string())
                                .unwrap_or_else(|| "<no uid>".to_string());
                            self.verified_fp = Some(fp);
                            self.verified_uid = Some(uid);
                        }
                        Err(e) => {
                            self.verification_error = Some(e.to_string());
                        }
                    }
                }
            }
        }
        if found_good {
            Ok(())
        } else {
            let reason = self
                .verification_error
                .clone()
                .unwrap_or_else(|| "No valid signatures found".to_string());
            Err(anyhow::anyhow!(reason).into())
        }
    }
}

/// Verify a detached PGP signature.
///
/// Returns `(fingerprint, uid)` on success.
fn verify_detached(
    artifact: &[u8],
    sig: &[u8],
    certs: &[CertPublic],
) -> Result<(String, String), VeriError> {
    let policy = StandardPolicy::new();

    let helper = SigHelper {
        certs: certs.to_vec(),
        verified_fp: None,
        verified_uid: None,
        verification_error: None,
    };

    let mut verifier = DetachedVerifierBuilder::from_bytes(sig)
        .map_err(|e| VeriError::SignatureInvalid {
            reason: format!("Failed to parse signature: {}", e),
        })?
        .with_policy(&policy, None, helper)
        .map_err(|e| VeriError::SignatureInvalid {
            reason: format!("Signature policy error: {}", e),
        })?;

    verifier.verify_bytes(artifact).map_err(|e| {
        VeriError::SignatureInvalid {
            reason: format!("Verification failed: {}", e),
        }
    })?;

    let helper = verifier.into_helper();
    let fp = helper
        .verified_fp
        .ok_or_else(|| VeriError::SignatureInvalid {
            reason: "Verification succeeded but fingerprint unavailable".to_string(),
        })?;
    let uid = helper.verified_uid.unwrap_or_else(|| "<no uid>".to_string());

    Ok((fp, uid))
}

/// Load trusted public key certificates from a directory.
///
/// Accepts armored (.asc) and binary (.pgp / .gpg) key files.
fn load_trusted_keys(
    trusted_keys_dir: Option<&Path>,
    artifact_path: &Path,
) -> Result<Vec<CertPublic>, VeriError> {
    let mut dirs_to_check: Vec<std::path::PathBuf> = Vec::new();

    if let Some(d) = trusted_keys_dir {
        dirs_to_check.push(d.to_path_buf());
    }

    // Also check for a `trusted_keys/` directory adjacent to the artifact.
    if let Some(parent) = artifact_path.parent() {
        let adjacent = parent.join("trusted_keys");
        if adjacent.is_dir() {
            dirs_to_check.push(adjacent);
        }
    }

    let mut certs = Vec::new();
    for dir in &dirs_to_check {
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "asc" | "pgp" | "gpg" | "pub") {
                continue;
            }
            match load_cert(path) {
                Ok(cert) => {
                    info!(key_path = %path.display(), "Loaded trusted key");
                    certs.push(cert);
                }
                Err(e) => {
                    warn!(key_path = %path.display(), error = %e, "Failed to load key; skipping");
                }
            }
        }
    }

    Ok(certs)
}

fn load_cert(path: &Path) -> Result<CertPublic, VeriError> {
    let bytes = std::fs::read(path).map_err(|e| VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    sequoia_openpgp::Cert::from_bytes(&bytes).map_err(|e| VeriError::KeyParseError {
        reason: format!("'{}': {}", path.display(), e),
    })
}

fn build_evidence(status: &str, sig_path: &str, fingerprint: &str, detail: &str) -> EvidenceItem {
    let mut inputs = HashMap::new();
    inputs.insert("sig_path".to_string(), sig_path.to_string());
    let mut outputs = HashMap::new();
    outputs.insert(
        "signature_status".to_string(),
        serde_json::Value::String(status.to_string()),
    );
    outputs.insert(
        "fingerprint".to_string(),
        serde_json::Value::String(fingerprint.to_string()),
    );
    outputs.insert(
        "detail".to_string(),
        serde_json::Value::String(detail.to_string()),
    );
    EvidenceItem::new("signature", inputs, outputs, HashMap::new())
}

fn build_evidence_verified(sig_path: &str, fingerprint: &str, uid: &str) -> EvidenceItem {
    let mut inputs = HashMap::new();
    inputs.insert("sig_path".to_string(), sig_path.to_string());
    let mut outputs = HashMap::new();
    outputs.insert(
        "signature_status".to_string(),
        serde_json::Value::String("verified".to_string()),
    );
    outputs.insert(
        "fingerprint".to_string(),
        serde_json::Value::String(fingerprint.to_string()),
    );
    outputs.insert(
        "signer_uid".to_string(),
        serde_json::Value::String(uid.to_string()),
    );
    EvidenceItem::new("signature", inputs, outputs, HashMap::new())
}
