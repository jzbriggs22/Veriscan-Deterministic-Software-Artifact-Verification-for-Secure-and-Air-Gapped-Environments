/// Hash stage: compute and verify cryptographic digests.
///
/// Computes SHA-256 and SHA-512 of the artifact. When expected checksums are
/// provided (via CLI or checksum files adjacent to the artifact), they are
/// compared and a mismatch is a hard FAILED – not a warning.
use crate::config::Policy;
use crate::error::VeriError;
use crate::evidence::EvidenceItem;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use tracing::info;

/// Result of the hash stage.
#[derive(Debug)]
pub struct HashResult {
    pub sha256: String,
    pub sha512: String,
    pub expected_sha256_matched: Option<bool>,
    pub expected_sha512_matched: Option<bool>,
    pub evidence: Vec<EvidenceItem>,
}

/// Run the hash stage.
///
/// - Computes SHA-256 and SHA-512 of `artifact_path`.
/// - If `expected_sha256` is provided, verifies the digest matches.
/// - If `expected_sha512` is provided, verifies the digest matches.
/// - Additionally searches for adjacent `<filename>.sha256` / `<filename>.sha512`
///   checksum files and verifies them if `policy.require_checksums` is true.
pub async fn run(
    artifact_path: &Path,
    policy: &Policy,
    expected_sha256: Option<&str>,
    expected_sha512: Option<&str>,
) -> Result<HashResult, VeriError> {
    info!(stage = "hash", path = %artifact_path.display(), "Computing digests");

    let (sha256, sha512) = compute_both(artifact_path)?;

    info!(sha256 = %sha256, sha512 = %sha512, "Digests computed");

    // Collect all expected checksums: explicit CLI args + adjacent checksum files.
    let eff_sha256 = resolve_expected_checksum(
        artifact_path,
        expected_sha256,
        "sha256",
        policy.require_checksums,
    )?;
    let eff_sha512 = resolve_expected_checksum(
        artifact_path,
        expected_sha512,
        "sha512",
        policy.require_checksums,
    )?;

    // Verify.
    let mut sha256_matched: Option<bool> = None;
    if let Some(expected) = &eff_sha256 {
        let exp_clean = expected.trim().to_lowercase();
        let matches = exp_clean == sha256;
        sha256_matched = Some(matches);
        if !matches {
            return Err(VeriError::HashMismatch {
                expected: exp_clean,
                actual: sha256.clone(),
            });
        }
        info!(sha256 = %sha256, "SHA-256 verified against expected");
    }

    let mut sha512_matched: Option<bool> = None;
    if let Some(expected) = &eff_sha512 {
        let exp_clean = expected.trim().to_lowercase();
        let matches = exp_clean == sha512;
        sha512_matched = Some(matches);
        if !matches {
            return Err(VeriError::HashMismatch {
                expected: exp_clean,
                actual: sha512.clone(),
            });
        }
        info!(sha512 = %sha512, "SHA-512 verified against expected");
    }

    let mut inputs = HashMap::new();
    inputs.insert(
        "artifact_path".to_string(),
        artifact_path.display().to_string(),
    );
    if let Some(e) = &eff_sha256 {
        inputs.insert("expected_sha256".to_string(), e.clone());
    }
    if let Some(e) = &eff_sha512 {
        inputs.insert("expected_sha512".to_string(), e.clone());
    }

    let mut outputs = HashMap::new();
    outputs.insert(
        "sha256".to_string(),
        serde_json::Value::String(sha256.clone()),
    );
    outputs.insert(
        "sha512".to_string(),
        serde_json::Value::String(sha512.clone()),
    );
    if let Some(m) = sha256_matched {
        outputs.insert(
            "sha256_matched".to_string(),
            serde_json::Value::Bool(m),
        );
    }
    if let Some(m) = sha512_matched {
        outputs.insert(
            "sha512_matched".to_string(),
            serde_json::Value::Bool(m),
        );
    }

    let evidence = EvidenceItem::new("hash", inputs, outputs, HashMap::new());

    Ok(HashResult {
        sha256,
        sha512,
        expected_sha256_matched: sha256_matched,
        expected_sha512_matched: sha512_matched,
        evidence: vec![evidence],
    })
}

/// Compute SHA-256 and SHA-512 of a file in a single streaming pass.
fn compute_both(path: &Path) -> Result<(String, String), VeriError> {
    let mut file = std::fs::File::open(path).map_err(|e| VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut sha256_hasher = Sha256::new();
    let mut sha512_hasher = Sha512::new();
    let mut buf = [0u8; 65_536];

    loop {
        let n = file.read(&mut buf).map_err(|e| VeriError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        sha256_hasher.update(&buf[..n]);
        sha512_hasher.update(&buf[..n]);
    }

    Ok((
        hex::encode(sha256_hasher.finalize()),
        hex::encode(sha512_hasher.finalize()),
    ))
}

/// Resolve the effective expected checksum for `algorithm`.
///
/// Priority:
/// 1. Explicit CLI argument (`explicit`).
/// 2. Adjacent checksum file (`<artifact>.<algorithm>` or `<artifact>.<ALGORITHM>SUM`).
/// 3. If `require_checksums` is true and no source found → hard error.
fn resolve_expected_checksum(
    artifact_path: &Path,
    explicit: Option<&str>,
    algorithm: &str,
    require_checksums: bool,
) -> Result<Option<String>, VeriError> {
    if let Some(e) = explicit {
        return Ok(Some(e.to_string()));
    }

    // Check for adjacent checksum files.
    let candidates = [
        // Appended lowercase form (`artifact.tar.gz.sha256`) — the convention
        // used by bundle creation and the demo tooling.
        Some(format!("{}.{}", artifact_path.display(), algorithm)),
        artifact_path
            .with_extension(algorithm)
            .to_str()
            .map(str::to_string),
        Some(format!(
            "{}.{}",
            artifact_path.display(),
            algorithm.to_uppercase()
        )),
        Some(format!("{}.{}sum", artifact_path.display(), algorithm)),
    ];

    for candidate in candidates.iter().flatten() {
        let p = Path::new(candidate);
        if p.exists() {
            let content = std::fs::read_to_string(p).map_err(|e| VeriError::Io {
                path: p.display().to_string(),
                source: e,
            })?;
            // Checksum files may contain "<hash>  <filename>" (GNU coreutils format).
            let hash = content
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if !hash.is_empty() {
                return Ok(Some(hash));
            }
        }
    }

    if require_checksums {
        return Err(VeriError::Internal(format!(
            "Policy requires checksums but no {} checksum found for '{}'",
            algorithm,
            artifact_path.display()
        )));
    }

    Ok(None)
}
