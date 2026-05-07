/// Acquire stage: obtain the artifact from a local path or a URL.
///
/// For URL sources, the file is downloaded to a temporary location.
/// URL is validated against the policy denylist before any network activity.
/// No execution of the artifact occurs at any point.
use crate::config::Policy;
use crate::error::VeriError;
use crate::evidence::EvidenceItem;
use crate::util::fs::{file_size, filename_str, sha256_file};
use crate::util::net::{build_client, check_url_allowed};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn};

/// Result of the acquire stage.
#[derive(Debug)]
pub struct AcquireResult {
    /// Path to the artifact on local disk (may be a temp file for URL sources).
    pub local_path: PathBuf,
    /// Original source string (local path or URL).
    pub source: String,
    /// Filename component of the source.
    pub filename: String,
    /// Artifact size in bytes.
    pub size_bytes: u64,
    /// SHA-256 of the acquired artifact (computed immediately after acquire).
    pub sha256_at_acquire: String,
    /// Evidence produced by this stage.
    pub evidence: Vec<EvidenceItem>,
    /// Temporary file handle (kept alive to prevent cleanup until we're done).
    pub _temp_file: Option<tempfile::NamedTempFile>,
}

/// Run the acquire stage.
///
/// `source` may be a filesystem path or an https:// URL.
/// `policy` is consulted for network permission and URL denylist.
pub async fn run(source: &str, policy: &Policy) -> Result<AcquireResult, VeriError> {
    info!(stage = "acquire", source = source, "Starting acquire stage");

    let is_url = source.starts_with("http://") || source.starts_with("https://");

    if is_url && !policy.allow_network {
        return Err(VeriError::NetworkDeniedByPolicy);
    }

    let (local_path, temp_file): (PathBuf, Option<tempfile::NamedTempFile>) = if is_url {
        acquire_url(source, policy).await?
    } else {
        let p = PathBuf::from(source);
        if !p.exists() {
            return Err(VeriError::ArtifactNotFound {
                path: source.to_string(),
            });
        }
        (p, None)
    };

    let size_bytes = file_size(&local_path)?;
    let sha256_at_acquire = sha256_file(&local_path)?;
    let filename = filename_str(&local_path);

    info!(
        stage = "acquire",
        local_path = %local_path.display(),
        size_bytes = size_bytes,
        sha256 = %sha256_at_acquire,
        "Artifact acquired"
    );

    let mut inputs = HashMap::new();
    inputs.insert("source".to_string(), source.to_string());
    inputs.insert("local_path".to_string(), local_path.display().to_string());

    let mut outputs = HashMap::new();
    outputs.insert(
        "size_bytes".to_string(),
        serde_json::Value::Number(serde_json::Number::from(size_bytes)),
    );
    outputs.insert(
        "sha256_at_acquire".to_string(),
        serde_json::Value::String(sha256_at_acquire.clone()),
    );
    outputs.insert(
        "filename".to_string(),
        serde_json::Value::String(filename.clone()),
    );
    outputs.insert(
        "source_type".to_string(),
        serde_json::Value::String(if is_url { "url" } else { "local" }.to_string()),
    );

    let evidence = EvidenceItem::new("acquire", inputs, outputs, HashMap::new());

    Ok(AcquireResult {
        local_path,
        source: source.to_string(),
        filename,
        size_bytes,
        sha256_at_acquire,
        evidence: vec![evidence],
        _temp_file: temp_file,
    })
}

async fn acquire_url(
    url: &str,
    policy: &Policy,
) -> Result<(PathBuf, Option<tempfile::NamedTempFile>), VeriError> {
    // Validate against denylist before touching the network.
    check_url_allowed(url, &policy.url_patterns_denylist)?;

    // Warn if http:// (not https://) — not blocked but flagged.
    if url.starts_with("http://") {
        warn!(url = url, "Acquiring over plain HTTP; consider using HTTPS");
    }

    let client = build_client(policy.network_timeout_seconds)?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(VeriError::Network)?;

    let status = response.status();
    if !status.is_success() {
        return Err(VeriError::VtApiError {
            status: status.as_u16(),
            body: format!("HTTP {} downloading artifact from '{}'", status, url),
        });
    }

    let bytes = response.bytes().await.map_err(VeriError::Network)?;

    // Write to a named temp file in /tmp; file is cleaned up when the
    // NamedTempFile handle is dropped (i.e., when AcquireResult is dropped).
    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| VeriError::Io {
        path: "/tmp".to_string(),
        source: e,
    })?;

    use std::io::Write;
    tmp.write_all(&bytes).map_err(|e| VeriError::Io {
        path: tmp.path().display().to_string(),
        source: e,
    })?;

    let path = tmp.path().to_path_buf();
    Ok((path, Some(tmp)))
}
