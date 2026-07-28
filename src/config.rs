/// Policy and configuration structures for veriscan.
///
/// Policies are YAML documents that fully specify verification behaviour.
/// There are no hidden defaults that silently bypass checks; every behaviour
/// is declared and auditable.
use crate::error::VeriError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Top-level policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Human-readable policy name, included in all reports.
    pub name: String,

    /// Policy document version for change tracking.
    pub version: String,

    /// Require a valid PGP detached signature for the artifact.
    pub require_signature: bool,

    /// Permit outbound network calls (reputation check, URL download, etc.).
    /// Set to false for air-gapped enforcement.
    pub allow_network: bool,

    /// Require that at least one checksum file (sha256/sha512) is present and
    /// matches the artifact.
    pub require_checksums: bool,

    /// Phase-II hook: reject artifacts without a verifiable SBOM attachment.
    /// Currently produces UNVERIFIED when true (not yet enforced as FAILED)
    /// to allow gradual adoption.
    pub require_sbom: bool,

    /// Require a successful reputation lookup; absence of result is UNVERIFIED
    /// or FAILED depending on `reputation_failure_is_fatal`.
    pub reputation_required: bool,

    /// When true, inability to obtain reputation data is FAILED rather than
    /// UNVERIFIED.
    #[serde(default)]
    pub reputation_failure_is_fatal: bool,

    /// Require a successful malware scan; absence of scanner is UNVERIFIED or
    /// FAILED depending on `malware_failure_is_fatal`.
    pub malware_scan_required: bool,

    /// When true, inability to run the malware scanner is FAILED.
    #[serde(default)]
    pub malware_failure_is_fatal: bool,

    /// File type labels (from inspection stage) that are denied outright.
    /// Example: ["application/x-dosexec"] or ["EXE", "DLL"]
    #[serde(default)]
    pub deny_file_types: Vec<String>,

    /// Allowed PGP signer fingerprints. When non-empty, a signature from a
    /// key not in this list is treated as SignerNotAllowed (FAILED).
    #[serde(default)]
    pub allow_signers: Vec<String>,

    /// Artifacts with computed Shannon entropy (0–8 bits) above this threshold
    /// are flagged as potentially packed/encrypted. Does not fail by itself;
    /// combines with other policy rules.
    #[serde(default = "default_entropy_threshold")]
    pub max_entropy_threshold: f64,

    /// URL substring/prefix denylist. Artifact sources matching any entry are
    /// rejected before download.
    #[serde(default)]
    pub url_patterns_denylist: Vec<String>,

    /// How to handle executable artifacts (ELF, PE, Mach-O, scripts).
    #[serde(default)]
    pub executable_handling: ExecutableHandling,

    /// Explicit rules mapping observable conditions to policy verdicts.
    #[serde(default)]
    pub decision_matrix: Vec<DecisionRule>,

    /// Absolute path to the ClamAV scanner binary (`clamscan`).
    /// If null/absent, malware scanning is skipped (UNVERIFIED unless
    /// `malware_failure_is_fatal`).
    #[serde(default)]
    pub malware_tool_path: Option<String>,

    /// Environment variable name that holds the VirusTotal API key.
    /// The key itself is NEVER stored in the policy file.
    #[serde(default = "default_vt_env")]
    pub vt_api_key_env: String,

    /// Local directory for caching reputation query results.
    #[serde(default = "default_reputation_cache_dir")]
    pub reputation_cache_dir: String,

    /// TTL for cached reputation results in seconds (default: 24 h).
    #[serde(default = "default_reputation_cache_ttl")]
    pub reputation_cache_ttl_seconds: u64,

    /// Timeout for external subprocess calls (ClamAV) in seconds.
    #[serde(default = "default_subprocess_timeout")]
    pub subprocess_timeout_seconds: u64,

    /// Timeout for network calls in seconds.
    #[serde(default = "default_network_timeout")]
    pub network_timeout_seconds: u64,

    /// Maximum bytes to capture from subprocess stdout/stderr.
    #[serde(default = "default_max_output_bytes")]
    pub max_subprocess_output_bytes: usize,

    /// Maximum number of strings to extract during inspection.
    #[serde(default = "default_max_strings")]
    pub max_inspection_strings: usize,

    /// Minimum printable-character run length to qualify as an extracted string.
    #[serde(default = "default_min_string_len")]
    pub min_string_length: usize,

    /// Maximum bytes to scan for entropy computation (avoids cost on huge files).
    #[serde(default = "default_entropy_sample_bytes")]
    pub entropy_sample_bytes: usize,
}

fn default_entropy_threshold() -> f64 {
    7.5
}
fn default_vt_env() -> String {
    "VT_API_KEY".to_string()
}
fn default_reputation_cache_dir() -> String {
    "/tmp/veriscan_reputation_cache".to_string()
}
fn default_reputation_cache_ttl() -> u64 {
    86_400
}
fn default_subprocess_timeout() -> u64 {
    120
}
fn default_network_timeout() -> u64 {
    30
}
fn default_max_output_bytes() -> usize {
    65_536
}
fn default_max_strings() -> usize {
    1_000
}
fn default_min_string_len() -> usize {
    6
}
fn default_entropy_sample_bytes() -> usize {
    1_048_576
}

/// How the tool treats executable file types.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableHandling {
    /// Allow executables regardless of signature state.
    Allow,
    /// Block unsigned executables (require_signature must also be true or
    /// this has no additional effect beyond require_signature).
    #[default]
    BlockUnsigned,
    /// Deny all executables outright regardless of signature.
    DenyAll,
}

/// A single rule in the policy decision matrix.
///
/// Rules are evaluated in order; the first matching rule applies.
/// If no rule matches, the default verdict is VERIFIED (all checks passed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRule {
    /// Human-readable description of what this rule detects.
    pub description: String,

    /// Condition expression (simple DSL evaluated by the policy stage).
    pub condition: RuleCondition,

    /// Verdict to apply when the condition matches.
    pub verdict: RuleVerdict,
}

/// Condition types for decision rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    /// Trigger when malware is detected.
    MalwareDetected,
    /// Trigger when signature is missing.
    SignatureMissing,
    /// Trigger when signature is invalid.
    SignatureInvalid,
    /// Trigger when signer is not in allow list.
    SignerNotAllowed,
    /// Trigger when checksum does not match.
    ChecksumMismatch,
    /// Trigger when entropy exceeds threshold.
    HighEntropy,
    /// Trigger when the file type is in the deny list.
    DeniedFileType,
    /// Trigger when reputation marks artifact as malicious.
    ReputationMalicious,
    /// Trigger when reputation is unavailable and required.
    ReputationUnavailable,
    /// Trigger when malware scanner is missing and scan required.
    MalwareScanUnavailable,
    /// Trigger when SBOM is required but absent (phase II).
    SbomMissing,
    /// Always trigger (used for default/fallback rules).
    Always,
}

/// Verdict applied by a matching rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerdict {
    /// Definitive failure; pipeline stops here.
    Failed,
    /// Unverified; noted but not immediately fatal (policy may still allow).
    Unverified,
    /// Explicitly verified by this rule (use for positive confirmations).
    Verified,
}

impl Policy {
    /// Load a policy from a YAML file.
    pub fn load(path: &Path) -> Result<Self, VeriError> {
        let content = std::fs::read_to_string(path).map_err(|e| VeriError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let policy: Policy =
            serde_yaml::from_str(&content).map_err(|e| VeriError::PolicyParseError {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
        policy.validate()?;
        Ok(policy)
    }

    /// Load the embedded default policy (compiled into the binary).
    pub fn default_policy() -> Result<Self, VeriError> {
        let content = include_str!("../policies/default.yaml");
        let policy: Policy =
            serde_yaml::from_str(content).map_err(|e| VeriError::PolicyParseError {
                path: "<embedded:default>".to_string(),
                reason: e.to_string(),
            })?;
        policy.validate()?;
        Ok(policy)
    }

    /// Validate policy invariants.
    pub fn validate(&self) -> Result<(), VeriError> {
        if self.name.is_empty() {
            return Err(VeriError::PolicyInvalid {
                reason: "policy.name must not be empty".to_string(),
            });
        }
        if self.max_entropy_threshold < 0.0 || self.max_entropy_threshold > 8.0 {
            return Err(VeriError::PolicyInvalid {
                reason: format!(
                    "max_entropy_threshold must be between 0.0 and 8.0, got {}",
                    self.max_entropy_threshold
                ),
            });
        }
        // Validate that allow_signers entries look like hex fingerprints
        for fp in &self.allow_signers {
            let clean = fp.replace(' ', "");
            if clean.len() != 40 && clean.len() != 64 {
                return Err(VeriError::PolicyInvalid {
                    reason: format!(
                        "allow_signers entry '{}' does not look like a v4 (40 hex) or v5 (64 hex) fingerprint",
                        fp
                    ),
                });
            }
            if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(VeriError::PolicyInvalid {
                    reason: format!("allow_signers entry '{}' contains non-hex characters", fp),
                });
            }
        }
        Ok(())
    }

    /// Return a deterministic SHA-256 digest of the policy content.
    /// Included in reports so auditors can verify the exact policy used.
    pub fn digest(&self) -> String {
        let canonical =
            serde_json::to_string(self).unwrap_or_else(|_| "<unserializable>".to_string());
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Runtime configuration (CLI overrides on top of policy).
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub policy: Policy,
    pub correlation_id: String,
    pub offline_mode: bool,
    pub report_json_path: Option<std::path::PathBuf>,
    pub report_md_path: Option<std::path::PathBuf>,
    pub audit_log_path: Option<std::path::PathBuf>,
    pub expected_sha256: Option<String>,
    pub expected_sha512: Option<String>,
    pub trusted_keys_dir: Option<std::path::PathBuf>,
    pub detached_sig_path: Option<std::path::PathBuf>,
}
