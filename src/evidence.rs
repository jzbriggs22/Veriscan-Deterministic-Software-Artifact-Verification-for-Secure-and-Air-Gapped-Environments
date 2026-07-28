/// Evidence model for veriscan.
///
/// Every verification decision is backed by structured evidence. Evidence items
/// are collected per pipeline stage and assembled into the final report. Each
/// item carries its own deterministic identifier (SHA-256 of its canonical
/// representation) to support chain-of-custody and tamper detection in the
/// report itself.
use crate::util::time::iso8601_now;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A single piece of verification evidence produced by one pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// ISO 8601 UTC timestamp when this evidence was collected.
    pub timestamp: String,

    /// Canonical name of the pipeline stage that produced this evidence.
    pub stage_name: String,

    /// Named inputs to this stage (file paths, URLs, key fingerprints, …).
    pub inputs: HashMap<String, String>,

    /// Named outputs (hashes, scan results, parsed fields, …).
    /// Values are typed JSON to avoid information loss.
    pub outputs: HashMap<String, serde_json::Value>,

    /// Version strings of any external tools invoked (clamscan, gpg, …).
    pub tool_versions: HashMap<String, String>,

    /// SHA-256 of the canonical serialisation of this evidence item.
    /// Allows downstream consumers to detect tampering of the evidence record.
    pub deterministic_id: String,
}

impl EvidenceItem {
    /// Construct an evidence item with an automatically computed deterministic ID.
    pub fn new(
        stage_name: impl Into<String>,
        inputs: HashMap<String, String>,
        outputs: HashMap<String, serde_json::Value>,
        tool_versions: HashMap<String, String>,
    ) -> Self {
        let stage_name = stage_name.into();
        let timestamp = iso8601_now();

        // Build canonical form: stage_name + sorted inputs + sorted outputs.
        // Sort keys to ensure determinism regardless of insertion order.
        let mut canonical_parts: Vec<String> = Vec::new();
        canonical_parts.push(format!("stage:{}", stage_name));
        canonical_parts.push(format!("timestamp:{}", timestamp));

        let mut sorted_inputs: Vec<_> = inputs.iter().collect();
        sorted_inputs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in &sorted_inputs {
            canonical_parts.push(format!("in:{}={}", k, v));
        }

        // Sort outputs by key; serialize values as compact JSON.
        let mut sorted_outputs: Vec<_> = outputs.iter().collect();
        sorted_outputs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in &sorted_outputs {
            canonical_parts.push(format!(
                "out:{}={}",
                k,
                serde_json::to_string(v).unwrap_or_default()
            ));
        }

        let canonical = canonical_parts.join("|");
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let deterministic_id = hex::encode(hasher.finalize());

        EvidenceItem {
            timestamp,
            stage_name,
            inputs,
            outputs,
            tool_versions,
            deterministic_id,
        }
    }

    /// Convenience builder for stages that produce simple key/value outputs.
    pub fn builder(stage_name: impl Into<String>) -> EvidenceBuilder {
        EvidenceBuilder::new(stage_name)
    }
}

/// Fluent builder for EvidenceItem.
pub struct EvidenceBuilder {
    stage_name: String,
    inputs: HashMap<String, String>,
    outputs: HashMap<String, serde_json::Value>,
    tool_versions: HashMap<String, String>,
}

impl EvidenceBuilder {
    pub fn new(stage_name: impl Into<String>) -> Self {
        Self {
            stage_name: stage_name.into(),
            inputs: HashMap::new(),
            outputs: HashMap::new(),
            tool_versions: HashMap::new(),
        }
    }

    pub fn input(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inputs.insert(key.into(), value.into());
        self
    }

    pub fn output(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.outputs.insert(key.into(), value.into());
        self
    }

    pub fn output_str(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.outputs
            .insert(key.into(), serde_json::Value::String(value.into()));
        self
    }

    pub fn output_bool(mut self, key: impl Into<String>, value: bool) -> Self {
        self.outputs
            .insert(key.into(), serde_json::Value::Bool(value));
        self
    }

    pub fn output_u64(mut self, key: impl Into<String>, value: u64) -> Self {
        self.outputs.insert(
            key.into(),
            serde_json::Value::Number(serde_json::Number::from(value)),
        );
        self
    }

    pub fn tool_version(mut self, tool: impl Into<String>, version: impl Into<String>) -> Self {
        self.tool_versions.insert(tool.into(), version.into());
        self
    }

    pub fn build(self) -> EvidenceItem {
        EvidenceItem::new(
            self.stage_name,
            self.inputs,
            self.outputs,
            self.tool_versions,
        )
    }
}

/// The typed verification status produced by policy evaluation.
///
/// Using an explicit enum prevents boolean confusion and forces callers to
/// handle all three outcomes at the type level.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum VerificationStatus {
    /// All required checks passed; artifact is considered verified under the
    /// applied policy.
    Verified,

    /// Some checks could not be completed (e.g., VT unavailable, optional sig
    /// missing) but nothing was definitively bad. Policy determines whether
    /// UNVERIFIED is acceptable.
    Unverified {
        reason: String,
        evidence: Vec<EvidenceItem>,
    },

    /// A definitive failure: hash mismatch, invalid signature, malware
    /// detected, policy hard block, etc.
    Failed {
        reason: String,
        evidence: Vec<EvidenceItem>,
    },
}

impl PartialEq for VerificationStatus {
    fn eq(&self, other: &Self) -> bool {
        // Compare status variant only (evidence lists may differ).
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl VerificationStatus {
    /// Return the process exit code defined by veriscan's CI gating spec.
    pub fn exit_code(&self) -> i32 {
        match self {
            VerificationStatus::Verified => 0,
            VerificationStatus::Unverified { .. } => 10,
            VerificationStatus::Failed { .. } => 20,
        }
    }

    /// Return the short label used in CLI output and report header.
    pub fn label(&self) -> &'static str {
        match self {
            VerificationStatus::Verified => "VERIFIED",
            VerificationStatus::Unverified { .. } => "UNVERIFIED",
            VerificationStatus::Failed { .. } => "FAILED",
        }
    }

    /// Return true only for Verified.
    pub fn is_verified(&self) -> bool {
        matches!(self, VerificationStatus::Verified)
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, VerificationStatus::Failed { .. })
    }

    pub fn is_unverified(&self) -> bool {
        matches!(self, VerificationStatus::Unverified { .. })
    }
}

/// Aggregated results from all pipeline stages, fed into the policy evaluator.
#[derive(Debug, Clone, Default)]
pub struct PipelineResults {
    pub hash_sha256: Option<String>,
    pub hash_sha512: Option<String>,
    pub expected_sha256_matched: Option<bool>,
    pub expected_sha512_matched: Option<bool>,
    pub signature_status: SignatureResult,
    pub malware_status: MalwareResult,
    pub inspection: InspectionResult,
    pub reputation: ReputationResult,
    pub artifact_size_bytes: u64,
    pub artifact_filename: String,
    pub file_type: String,
}

/// Signature verification outcome from the signature stage.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum SignatureResult {
    #[default]
    NotChecked,
    Verified {
        signer_uid: String,
        fingerprint: String,
    },
    Missing,
    Invalid {
        reason: String,
    },
    SignerNotAllowed {
        fingerprint: String,
    },
}

/// Malware scan outcome.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum MalwareResult {
    #[default]
    NotChecked,
    Clean {
        engine: String,
        version: String,
    },
    Detected {
        engine: String,
        version: String,
        detections: Vec<String>,
    },
    ToolMissing {
        tool_path: String,
    },
    ScanError {
        reason: String,
    },
}

/// Static inspection outcome.
#[derive(Debug, Clone, Default)]
pub struct InspectionResult {
    pub file_type: String,
    pub entropy: f64,
    pub entropy_flagged: bool,
    pub indicators: Vec<String>,
    pub strings_excerpt: Vec<String>,
    pub is_executable: bool,
    pub is_script: bool,
}

/// Reputation check outcome.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum ReputationResult {
    #[default]
    NotChecked,
    Clean {
        engines_total: u32,
        engines_detected: u32,
        source: String,
        last_seen: Option<String>,
        link: Option<String>,
    },
    Malicious {
        engines_total: u32,
        engines_detected: u32,
        source: String,
        last_seen: Option<String>,
        link: Option<String>,
    },
    Unknown {
        reason: String,
    },
    ApiKeyMissing,
    Unavailable {
        reason: String,
    },
}
