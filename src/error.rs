/// Typed error hierarchy for veriscan.
///
/// All errors carry context that will be included in evidence. No error
/// information is suppressed or collapsed into a generic "something failed."
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VeriError {
    // ── I/O ────────────────────────────────────────────────────────────────
    #[error("I/O error accessing '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Path traversal attempt detected in '{path}'")]
    PathTraversal { path: String },

    #[error("Artifact path does not exist: '{path}'")]
    ArtifactNotFound { path: String },

    // ── Network ────────────────────────────────────────────────────────────
    #[error("Network operation failed: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Network access denied by policy")]
    NetworkDeniedByPolicy,

    #[error("URL denied by policy denylist: '{url}'")]
    UrlDenied { url: String },

    // ── Hash ───────────────────────────────────────────────────────────────
    #[error("Hash mismatch: expected '{expected}', got '{actual}'")]
    HashMismatch { expected: String, actual: String },

    #[error("Artifact mutation detected between stages: hash changed from '{before}' to '{after}'")]
    ArtifactMutated { before: String, after: String },

    // ── Signature ──────────────────────────────────────────────────────────
    #[error("PGP signature verification failed: {reason}")]
    SignatureInvalid { reason: String },

    #[error("No PGP signature found for artifact")]
    SignatureMissing,

    #[error("Signer fingerprint '{fingerprint}' is not in the allow list")]
    SignerNotAllowed { fingerprint: String },

    #[error("PGP key parsing failed: {reason}")]
    KeyParseError { reason: String },

    // ── Bundle ─────────────────────────────────────────────────────────────
    #[error("Bundle manifest signature verification failed: {reason}")]
    ManifestSignatureInvalid { reason: String },

    #[error("Bundle file hash mismatch for '{file}': expected '{expected}', got '{actual}'")]
    BundleFileMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("Bundle is missing required file: '{file}'")]
    BundleFileMissing { file: String },

    #[error("Bundle directory does not exist or is not a directory: '{path}'")]
    BundleNotFound { path: String },

    #[error("Bundle manifest parse error: {reason}")]
    ManifestParseError { reason: String },

    // ── Malware Scan ───────────────────────────────────────────────────────
    #[error("Malware scan tool not found at '{path}'")]
    MalwareToolMissing { path: String },

    #[error("Malware scan timed out after {seconds}s")]
    MalwareScanTimeout { seconds: u64 },

    #[error("Malware scan process error: {reason}")]
    MalwareScanError { reason: String },

    // ── Reputation ────────────────────────────────────────────────────────
    #[error("VirusTotal API key not configured (set {env_var} environment variable)")]
    VtApiKeyMissing { env_var: String },

    #[error("VirusTotal API request failed with status {status}: {body}")]
    VtApiError { status: u16, body: String },

    #[error("VirusTotal request timed out")]
    VtTimeout,

    // ── Policy ────────────────────────────────────────────────────────────
    #[error("Policy file not found: '{path}'")]
    PolicyNotFound { path: String },

    #[error("Policy parse error in '{path}': {reason}")]
    PolicyParseError { path: String, reason: String },

    #[error("Policy validation failed: {reason}")]
    PolicyInvalid { reason: String },

    // ── Subprocess ────────────────────────────────────────────────────────
    #[error("Subprocess binary must be an absolute path, got: '{path}'")]
    SubprocessPathNotAbsolute { path: String },

    #[error("Subprocess '{binary}' timed out after {seconds}s")]
    SubprocessTimeout { binary: String, seconds: u64 },

    #[error("Subprocess '{binary}' failed with exit code {code}: {stderr}")]
    SubprocessFailed {
        binary: String,
        code: i32,
        stderr: String,
    },

    // ── Inspection ────────────────────────────────────────────────────────
    #[error("File type denied by policy: '{file_type}'")]
    DeniedFileType { file_type: String },

    // ── Internal ──────────────────────────────────────────────────────────
    #[error("Internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl VeriError {
    /// Return a stable machine-readable code for this error variant.
    /// Used in evidence and reports.
    pub fn code(&self) -> &'static str {
        match self {
            VeriError::Io { .. } => "ERR_IO",
            VeriError::PathTraversal { .. } => "ERR_PATH_TRAVERSAL",
            VeriError::ArtifactNotFound { .. } => "ERR_ARTIFACT_NOT_FOUND",
            VeriError::Network(_) => "ERR_NETWORK",
            VeriError::NetworkDeniedByPolicy => "ERR_NETWORK_POLICY",
            VeriError::UrlDenied { .. } => "ERR_URL_DENIED",
            VeriError::HashMismatch { .. } => "ERR_HASH_MISMATCH",
            VeriError::ArtifactMutated { .. } => "ERR_ARTIFACT_MUTATED",
            VeriError::SignatureInvalid { .. } => "ERR_SIG_INVALID",
            VeriError::SignatureMissing => "ERR_SIG_MISSING",
            VeriError::SignerNotAllowed { .. } => "ERR_SIGNER_NOT_ALLOWED",
            VeriError::KeyParseError { .. } => "ERR_KEY_PARSE",
            VeriError::ManifestSignatureInvalid { .. } => "ERR_MANIFEST_SIG_INVALID",
            VeriError::BundleFileMismatch { .. } => "ERR_BUNDLE_FILE_MISMATCH",
            VeriError::BundleFileMissing { .. } => "ERR_BUNDLE_FILE_MISSING",
            VeriError::BundleNotFound { .. } => "ERR_BUNDLE_NOT_FOUND",
            VeriError::ManifestParseError { .. } => "ERR_MANIFEST_PARSE",
            VeriError::MalwareToolMissing { .. } => "ERR_MALWARE_TOOL_MISSING",
            VeriError::MalwareScanTimeout { .. } => "ERR_MALWARE_TIMEOUT",
            VeriError::MalwareScanError { .. } => "ERR_MALWARE_SCAN",
            VeriError::VtApiKeyMissing { .. } => "ERR_VT_KEY_MISSING",
            VeriError::VtApiError { .. } => "ERR_VT_API",
            VeriError::VtTimeout => "ERR_VT_TIMEOUT",
            VeriError::PolicyNotFound { .. } => "ERR_POLICY_NOT_FOUND",
            VeriError::PolicyParseError { .. } => "ERR_POLICY_PARSE",
            VeriError::PolicyInvalid { .. } => "ERR_POLICY_INVALID",
            VeriError::SubprocessPathNotAbsolute { .. } => "ERR_SUBPROCESS_PATH",
            VeriError::SubprocessTimeout { .. } => "ERR_SUBPROCESS_TIMEOUT",
            VeriError::SubprocessFailed { .. } => "ERR_SUBPROCESS_FAILED",
            VeriError::DeniedFileType { .. } => "ERR_FILE_TYPE_DENIED",
            VeriError::Internal(_) => "ERR_INTERNAL",
            VeriError::Other(_) => "ERR_OTHER",
        }
    }
}
