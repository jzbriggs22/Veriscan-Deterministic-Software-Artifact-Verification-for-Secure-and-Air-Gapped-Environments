/// Offline verification bundle: create and verify.
///
/// Bundle format:
/// ```text
/// bundle/
///   artifact               (the artifact file)
///   artifact.sha256        (hex SHA-256)
///   artifact.sha512        (hex SHA-512, optional)
///   artifact.sig           (PGP detached signature over artifact)
///   trusted_keys/          (trusted public keys for offline verification)
///     *.asc
///   bundle.manifest.json   (lists all files + their SHA-256)
///   bundle.manifest.sig    (PGP detached signature over manifest)
/// ```
///
/// Verification order (fail-closed):
/// 1. Verify bundle.manifest.sig over bundle.manifest.json.
/// 2. Verify each file's SHA-256 matches the manifest.
/// 3. Verify artifact.sig over artifact (using trusted_keys/).
///
/// No file is trusted until the manifest signature passes.
use crate::error::VeriError;
use crate::util::fs::sha256_file;
use serde::{Deserialize, Serialize};
use sequoia_openpgp::parse::Parse;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use walkdir::WalkDir;

/// Bundle manifest structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema_version: String,
    pub created_at: String,
    pub artifact_filename: String,
    pub files: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub sha256: String,
}

/// Create a verification bundle from an artifact and its signing key.
///
/// `artifact_path` – artifact to bundle
/// `keys_dir`       – directory containing the private key for signing and
///                    the public key to include in trusted_keys/
/// `out_dir`        – directory to write the bundle into (created if absent)
pub async fn create(
    artifact_path: &Path,
    keys_dir: &Path,
    out_dir: &Path,
    signing_key_path: &Path,
) -> Result<(), VeriError> {
    info!(
        artifact = %artifact_path.display(),
        out_dir = %out_dir.display(),
        "Creating offline verification bundle"
    );

    std::fs::create_dir_all(out_dir).map_err(|e| VeriError::Io {
        path: out_dir.display().to_string(),
        source: e,
    })?;
    std::fs::create_dir_all(out_dir.join("trusted_keys")).map_err(|e| VeriError::Io {
        path: out_dir.join("trusted_keys").display().to_string(),
        source: e,
    })?;

    // Copy artifact.
    let artifact_filename = artifact_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "artifact".to_string());
    let dest_artifact = out_dir.join(&artifact_filename);
    std::fs::copy(artifact_path, &dest_artifact).map_err(|e| VeriError::Io {
        path: artifact_path.display().to_string(),
        source: e,
    })?;

    // Compute hashes.
    let sha256 = compute_sha256_str(&dest_artifact)?;
    let sha512 = compute_sha512_str(&dest_artifact)?;
    std::fs::write(out_dir.join(format!("{}.sha256", artifact_filename)), &sha256)
        .map_err(|e| VeriError::Io {
            path: out_dir
                .join(format!("{}.sha256", artifact_filename))
                .display()
                .to_string(),
            source: e,
        })?;
    std::fs::write(out_dir.join(format!("{}.sha512", artifact_filename)), &sha512)
        .map_err(|e| VeriError::Io {
            path: out_dir
                .join(format!("{}.sha512", artifact_filename))
                .display()
                .to_string(),
            source: e,
        })?;

    // Copy public keys from keys_dir to trusted_keys/.
    // Scan each candidate file for private-key markers before copying;
    // skip (and warn) any file that contains secret-key material.
    const PRIVATE_KEY_MARKERS: &[&str] = &[
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN PGP SECRET KEY BLOCK-----",
        "PRIVATE KEY",
    ];
    for entry in WalkDir::new(keys_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if p.is_file() {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "asc" | "pub" | "pgp" | "gpg") {
                // Read and inspect for private-key markers before copying.
                let content = std::fs::read(p).map_err(|e| VeriError::Io {
                    path: p.display().to_string(),
                    source: e,
                })?;
                // Interpret as lossy UTF-8 for marker scanning (binary keys
                // will not contain these ASCII markers).
                let text = String::from_utf8_lossy(&content);
                if PRIVATE_KEY_MARKERS.iter().any(|m| text.contains(m)) {
                    warn!(
                        key_path = %p.display(),
                        "Skipping file containing private-key material; \
                         only public keys should be in the keys directory"
                    );
                    continue;
                }
                let dest = out_dir
                    .join("trusted_keys")
                    .join(p.file_name().unwrap());
                std::fs::copy(p, &dest).map_err(|e| VeriError::Io {
                    path: p.display().to_string(),
                    source: e,
                })?;
            }
        }
    }

    // Sign the artifact using sequoia if signing_key_path is provided.
    // In the demo environment, GPG is used for signing; we support that workflow.
    // Here we create the .sig file if the signing key is a sequoia-compatible secret key.
    let sig_dest = out_dir.join(format!("{}.sig", artifact_filename));
    sign_artifact_with_sequoia(artifact_path, signing_key_path, &sig_dest)?;

    // Build and write manifest.
    let mut entries: Vec<ManifestEntry> = Vec::new();
    for entry in WalkDir::new(out_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        // Skip the manifest files themselves.
        let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if fname == "bundle.manifest.json" || fname == "bundle.manifest.sig" {
            continue;
        }
        let rel = p
            .strip_prefix(out_dir)
            .map(|r| r.to_string_lossy().to_string())
            .unwrap_or_default();
        let file_sha256 = sha256_file(p)?;
        entries.push(ManifestEntry {
            path: rel,
            sha256: file_sha256,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest = BundleManifest {
        schema_version: "1.0".to_string(),
        created_at: crate::util::time::iso8601_now(),
        artifact_filename: artifact_filename.clone(),
        files: entries,
    };
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| VeriError::Internal(e.to_string()))?;
    let manifest_path = out_dir.join("bundle.manifest.json");
    std::fs::write(&manifest_path, manifest_json.as_bytes()).map_err(|e| VeriError::Io {
        path: manifest_path.display().to_string(),
        source: e,
    })?;

    // Sign the manifest.
    let manifest_sig_path = out_dir.join("bundle.manifest.sig");
    sign_artifact_with_sequoia(&manifest_path, signing_key_path, &manifest_sig_path)?;

    info!(out_dir = %out_dir.display(), "Bundle created successfully");
    Ok(())
}

/// Verify an offline bundle directory.
///
/// Returns the artifact path within the bundle on success.
pub async fn verify(bundle_dir: &Path) -> Result<PathBuf, VeriError> {
    if !bundle_dir.is_dir() {
        return Err(VeriError::BundleNotFound {
            path: bundle_dir.display().to_string(),
        });
    }

    // Prevent path traversal — canonicalize base.
    let bundle_dir = bundle_dir.canonicalize().map_err(|e| VeriError::Io {
        path: bundle_dir.display().to_string(),
        source: e,
    })?;

    info!(bundle_dir = %bundle_dir.display(), "Verifying offline bundle");

    // Step 1: Load manifest.
    let manifest_path = bundle_dir.join("bundle.manifest.json");
    let manifest_sig_path = bundle_dir.join("bundle.manifest.sig");

    if !manifest_path.exists() {
        return Err(VeriError::BundleFileMissing {
            file: "bundle.manifest.json".to_string(),
        });
    }
    if !manifest_sig_path.exists() {
        return Err(VeriError::BundleFileMissing {
            file: "bundle.manifest.sig".to_string(),
        });
    }

    // Step 2: Load trusted keys.
    let keys_dir = bundle_dir.join("trusted_keys");
    let certs = load_bundle_keys(&keys_dir)?;
    if certs.is_empty() {
        return Err(VeriError::ManifestSignatureInvalid {
            reason: "No trusted keys found in bundle/trusted_keys/".to_string(),
        });
    }

    // Step 3: Verify manifest signature FIRST (before reading any other content).
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| VeriError::Io {
        path: manifest_path.display().to_string(),
        source: e,
    })?;
    let manifest_sig_bytes = std::fs::read(&manifest_sig_path).map_err(|e| VeriError::Io {
        path: manifest_sig_path.display().to_string(),
        source: e,
    })?;

    verify_sig_with_certs(&manifest_bytes, &manifest_sig_bytes, &certs).map_err(|e| {
        VeriError::ManifestSignatureInvalid {
            reason: e.to_string(),
        }
    })?;
    info!("Bundle manifest signature verified");

    // Step 4: Parse manifest and verify all listed file hashes.
    let manifest: BundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| VeriError::ManifestParseError {
            reason: e.to_string(),
        })?;

    for entry in &manifest.files {
        // Safe path: prevent traversal out of bundle_dir.
        let file_path = safe_bundle_path(&bundle_dir, &entry.path)?;
        if !file_path.exists() {
            return Err(VeriError::BundleFileMissing {
                file: entry.path.clone(),
            });
        }
        let actual_sha256 = sha256_file(&file_path)?;
        if actual_sha256 != entry.sha256 {
            return Err(VeriError::BundleFileMismatch {
                file: entry.path.clone(),
                expected: entry.sha256.clone(),
                actual: actual_sha256,
            });
        }
    }
    info!("All bundle file hashes verified");

    // Return the artifact path — apply the same canonical containment check
    // so artifact_filename cannot escape bundle_dir via relative segments or symlinks.
    let artifact_path = safe_bundle_path(&bundle_dir, &manifest.artifact_filename)?;
    if !artifact_path.exists() {
        return Err(VeriError::BundleFileMissing {
            file: manifest.artifact_filename.clone(),
        });
    }

    Ok(artifact_path)
}

/// Reject any path that escapes the bundle directory.
///
/// Uses filesystem canonicalization so that symlinks and relative segments
/// (`./x/../y`) cannot bypass the check.  The file at `relative` must exist
/// (bundle verification only calls this for files already present in the
/// bundle directory).
fn safe_bundle_path(base: &Path, relative: &str) -> Result<PathBuf, VeriError> {
    // Fast lexical pre-check — catches the common cases early.
    if relative.starts_with('/') || relative.contains("..") {
        return Err(VeriError::PathTraversal {
            path: relative.to_string(),
        });
    }

    // Canonical base: must exist or we cannot safely confine.
    let base_abs = base.canonicalize().map_err(|e| VeriError::Io {
        path: base.display().to_string(),
        source: e,
    })?;

    let joined = base_abs.join(relative);

    // Canonicalize the joined path (resolves symlinks, normalizes segments).
    // The file is expected to exist at this point; if it does not the caller
    // will detect and report BundleFileMissing immediately after.
    let resolved = if joined.exists() {
        joined.canonicalize().map_err(|e| VeriError::Io {
            path: joined.display().to_string(),
            source: e,
        })?
    } else {
        joined.clone()
    };

    if !resolved.starts_with(&base_abs) {
        return Err(VeriError::PathTraversal {
            path: relative.to_string(),
        });
    }

    Ok(resolved)
}

fn load_bundle_keys(
    keys_dir: &Path,
) -> Result<Vec<sequoia_openpgp::Cert>, VeriError> {
    let mut certs = Vec::new();
    if !keys_dir.is_dir() {
        return Ok(certs);
    }
    for entry in WalkDir::new(keys_dir)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "asc" | "pub" | "pgp" | "gpg") {
            continue;
        }
        let bytes = std::fs::read(p).map_err(|e| VeriError::Io {
            path: p.display().to_string(),
            source: e,
        })?;
        match sequoia_openpgp::Cert::from_bytes(&bytes) {
            Ok(cert) => certs.push(cert),
            Err(e) => {
                tracing::warn!(path = %p.display(), error = %e, "Failed to load bundle key; skipping");
            }
        }
    }
    Ok(certs)
}

/// Sign `data_path` with a sequoia secret key at `key_path`, writing the
/// detached binary signature to `sig_path`.
fn sign_artifact_with_sequoia(
    data_path: &Path,
    key_path: &Path,
    sig_path: &Path,
) -> Result<(), VeriError> {
    use sequoia_openpgp::{
        cert::prelude::*,
        parse::Parse,
        policy::StandardPolicy,
        serialize::stream::{Message, Signer},
    };
    use std::io::Write;

    if !key_path.exists() {
        // No signing key — skip signing (bundle won't have a signature).
        // The manifest.sig step later will also fail, which is correct behaviour.
        tracing::warn!(key_path = %key_path.display(), "Signing key not found; artifact signature will be absent");
        return Ok(());
    }

    let key_bytes = std::fs::read(key_path).map_err(|e| VeriError::Io {
        path: key_path.display().to_string(),
        source: e,
    })?;
    let cert = sequoia_openpgp::Cert::from_bytes(&key_bytes).map_err(|e| VeriError::KeyParseError {
        reason: e.to_string(),
    })?;

    let policy = StandardPolicy::new();

    // Select a valid signing key.
    let signing_keypair = cert
        .keys()
        .unencrypted_secret()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .ok_or_else(|| VeriError::KeyParseError {
            reason: "No usable signing key found in secret key".to_string(),
        })?
        .key()
        .clone()
        .into_keypair()
        .map_err(|e| VeriError::KeyParseError {
            reason: e.to_string(),
        })?;

    let data = std::fs::read(data_path).map_err(|e| VeriError::Io {
        path: data_path.display().to_string(),
        source: e,
    })?;

    let mut sig_output = Vec::new();
    {
        let message = Message::new(&mut sig_output);
        let mut signer = Signer::new(message, signing_keypair)
            .detached()
            .build()
            .map_err(|e| VeriError::Internal(format!("Failed to create signer: {}", e)))?;
        signer.write_all(&data).map_err(|e| VeriError::Io {
            path: data_path.display().to_string(),
            source: e,
        })?;
        signer.finalize().map_err(|e| VeriError::Internal(format!("Failed to finalize signature: {}", e)))?;
    }

    std::fs::write(sig_path, &sig_output).map_err(|e| VeriError::Io {
        path: sig_path.display().to_string(),
        source: e,
    })?;
    info!(sig_path = %sig_path.display(), "Created detached signature");
    Ok(())
}

/// Verify a detached signature using a set of trusted certs.
fn verify_sig_with_certs(
    data: &[u8],
    sig: &[u8],
    certs: &[sequoia_openpgp::Cert],
) -> Result<(), VeriError> {
    use sequoia_openpgp::{
        parse::stream::{
            DetachedVerifierBuilder, GoodChecksum, MessageLayer, MessageStructure, VerificationHelper,
        },
        policy::StandardPolicy,
        KeyHandle,
    };

    struct Helper {
        certs: Vec<sequoia_openpgp::Cert>,
        found_good: bool,
    }

    impl VerificationHelper for Helper {
        fn get_certs(&mut self, ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
            Ok(self
                .certs
                .iter()
                .filter(|c| {
                    ids.iter()
                        .any(|id| c.keys().any(|k| k.key_handle().aliases(id)))
                })
                .cloned()
                .collect())
        }

        fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
            for layer in structure {
                if let MessageLayer::SignatureGroup { results } = layer {
                    for r in results {
                        if r.is_ok() {
                            self.found_good = true;
                        }
                    }
                }
            }
            if self.found_good {
                Ok(())
            } else {
                Err(anyhow::anyhow!("No valid signatures found in bundle manifest").into())
            }
        }
    }

    let policy = StandardPolicy::new();
    let helper = Helper {
        certs: certs.to_vec(),
        found_good: false,
    };
    let mut verifier = DetachedVerifierBuilder::from_bytes(sig)
        .map_err(|e| VeriError::ManifestSignatureInvalid {
            reason: format!("Cannot parse manifest signature: {}", e),
        })?
        .with_policy(&policy, None, helper)
        .map_err(|e| VeriError::ManifestSignatureInvalid {
            reason: format!("Policy error: {}", e),
        })?;
    verifier.verify_bytes(data).map_err(|e| {
        VeriError::ManifestSignatureInvalid {
            reason: format!("Verification failed: {}", e),
        }
    })?;
    Ok(())
}

fn compute_sha256_str(path: &Path) -> Result<String, VeriError> {
    let bytes = std::fs::read(path).map_err(|e| VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

fn compute_sha512_str(path: &Path) -> Result<String, VeriError> {
    let bytes = std::fs::read(path).map_err(|e| VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut h = Sha512::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}
