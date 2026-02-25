/// Reputation check stage: VirusTotal hash lookup.
///
/// Only the SHA-256 hash is submitted to VirusTotal — the artifact bytes
/// are NEVER uploaded. The API key is read from an environment variable
/// (name configured in policy); it is never stored on disk, never logged.
///
/// Results are cached locally (configurable TTL) to minimise API traffic
/// and support partial offline operation.
use crate::config::Policy;
use crate::error::VeriError;
use crate::evidence::{EvidenceItem, ReputationResult};
use crate::util::net::build_client;
use crate::util::time::{iso8601_now, parse_iso8601};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug)]
pub struct ReputationStageResult {
    pub result: ReputationResult,
    pub evidence: Vec<EvidenceItem>,
}

/// Cached reputation record stored on disk.
#[derive(Debug, Serialize, Deserialize)]
struct CachedReputation {
    sha256: String,
    cached_at: String,
    result: CachedReputationResult,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedReputationResult {
    engines_total: u32,
    engines_detected: u32,
    reputation_label: String,
    last_seen: Option<String>,
    link: Option<String>,
}

/// Run the reputation check stage.
pub async fn run(
    sha256: &str,
    policy: &Policy,
    offline: bool,
) -> Result<ReputationStageResult, VeriError> {
    info!(stage = "reputation", sha256 = sha256, "Starting reputation check");

    if offline || !policy.allow_network {
        info!(stage = "reputation", "Offline/no-network mode; reputation check skipped");
        return Ok(ReputationStageResult {
            result: ReputationResult::Unknown {
                reason: "Offline mode: reputation check unavailable".to_string(),
            },
            evidence: vec![build_evidence_skipped("Offline mode")],
        });
    }

    // Check local cache first.
    if let Some(cached) = load_cache(sha256, policy) {
        info!(stage = "reputation", sha256 = sha256, "Cache hit for reputation");
        return Ok(build_from_cached(&cached));
    }

    // Read API key from environment — NEVER from config file.
    let api_key = std::env::var(&policy.vt_api_key_env).unwrap_or_default();
    if api_key.is_empty() {
        warn!(
            stage = "reputation",
            env_var = %policy.vt_api_key_env,
            "VT API key not set"
        );
        return Ok(ReputationStageResult {
            result: ReputationResult::ApiKeyMissing,
            evidence: vec![build_evidence_skipped("VT API key not configured")],
        });
    }

    // Query VirusTotal v3 API by hash only.
    let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256);
    let client = build_client(policy.network_timeout_seconds)?;

    let resp = client
        .get(&url)
        .header("x-apikey", &api_key)
        // API key must never appear in logs; we don't log the header.
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            warn!(stage = "reputation", error = %e, "VT request failed");
            return Ok(ReputationStageResult {
                result: ReputationResult::Unavailable {
                    reason: format!("Network error: {}", e),
                },
                evidence: vec![build_evidence_skipped(&format!("Network error: {}", e))],
            });
        }
    };

    let status = resp.status();

    if status.as_u16() == 404 {
        // Hash not found in VT — not necessarily clean, just unknown.
        info!(stage = "reputation", "Hash not found in VirusTotal");
        return Ok(ReputationStageResult {
            result: ReputationResult::Unknown {
                reason: "Hash not found in VirusTotal database".to_string(),
            },
            evidence: vec![build_evidence_skipped("Hash not in VT database")],
        });
    }

    if !status.is_success() {
        let body: String = resp
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".to_string());
        // Truncate body to prevent log injection.
        let body_excerpt: String = body.chars().take(256).collect();
        return Err(VeriError::VtApiError {
            status: status.as_u16(),
            body: body_excerpt,
        });
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| VeriError::Internal(format!("VT response parse: {}", e)))?;

    let stats = &body["data"]["attributes"]["last_analysis_stats"];
    let engines_total = (stats["malicious"].as_u64().unwrap_or(0)
        + stats["suspicious"].as_u64().unwrap_or(0)
        + stats["harmless"].as_u64().unwrap_or(0)
        + stats["undetected"].as_u64().unwrap_or(0)) as u32;
    let engines_detected = (stats["malicious"].as_u64().unwrap_or(0)
        + stats["suspicious"].as_u64().unwrap_or(0)) as u32;

    let last_seen = body["data"]["attributes"]["last_analysis_date"]
        .as_i64()
        .map(|ts| {
            chrono::DateTime::<Utc>::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default()
        });

    let link = body["data"]["links"]["self"]
        .as_str()
        .map(str::to_string);

    let reputation_label = if engines_detected == 0 {
        "clean".to_string()
    } else {
        "malicious".to_string()
    };

    let cached = CachedReputation {
        sha256: sha256.to_string(),
        cached_at: iso8601_now(),
        result: CachedReputationResult {
            engines_total,
            engines_detected,
            reputation_label: reputation_label.clone(),
            last_seen: last_seen.clone(),
            link: link.clone(),
        },
    };
    store_cache(sha256, &cached, policy);

    let rep_result = if engines_detected == 0 {
        ReputationResult::Clean {
            engines_total,
            engines_detected,
            source: "VirusTotal".to_string(),
            last_seen,
            link,
        }
    } else {
        ReputationResult::Malicious {
            engines_total,
            engines_detected,
            source: "VirusTotal".to_string(),
            last_seen,
            link,
        }
    };

    let evidence = build_evidence_result(sha256, &cached.result);
    Ok(ReputationStageResult {
        result: rep_result,
        evidence: vec![evidence],
    })
}

fn cache_path(sha256: &str, policy: &Policy) -> PathBuf {
    Path::new(&policy.reputation_cache_dir)
        .join(format!("{}.json", sha256))
}

fn load_cache(sha256: &str, policy: &Policy) -> Option<CachedReputation> {
    let path = cache_path(sha256, policy);
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    let cached: CachedReputation = serde_json::from_str(&content).ok()?;

    // Check TTL.
    let cached_at = parse_iso8601(&cached.cached_at)?;
    let age_secs = (Utc::now() - cached_at).num_seconds() as u64;
    if age_secs > policy.reputation_cache_ttl_seconds {
        return None;
    }
    Some(cached)
}

fn store_cache(sha256: &str, entry: &CachedReputation, policy: &Policy) {
    let dir = Path::new(&policy.reputation_cache_dir);
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!(error = %e, "Failed to create reputation cache dir");
        return;
    }
    let path = cache_path(sha256, policy);
    let json = match serde_json::to_string_pretty(entry) {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "Failed to serialize cache entry");
            return;
        }
    };
    if let Err(e) = std::fs::write(&path, json) {
        warn!(error = %e, path = %path.display(), "Failed to write reputation cache");
    }
}

fn build_from_cached(cached: &CachedReputation) -> ReputationStageResult {
    let r = &cached.result;
    let rep_result = if r.engines_detected == 0 {
        ReputationResult::Clean {
            engines_total: r.engines_total,
            engines_detected: r.engines_detected,
            source: "VirusTotal (cached)".to_string(),
            last_seen: r.last_seen.clone(),
            link: r.link.clone(),
        }
    } else {
        ReputationResult::Malicious {
            engines_total: r.engines_total,
            engines_detected: r.engines_detected,
            source: "VirusTotal (cached)".to_string(),
            last_seen: r.last_seen.clone(),
            link: r.link.clone(),
        }
    };
    let evidence = build_evidence_result(&cached.sha256, r);
    ReputationStageResult {
        result: rep_result,
        evidence: vec![evidence],
    }
}

fn build_evidence_skipped(reason: &str) -> EvidenceItem {
    let mut outputs = HashMap::new();
    outputs.insert(
        "reputation_status".to_string(),
        serde_json::Value::String("skipped".to_string()),
    );
    outputs.insert(
        "reason".to_string(),
        serde_json::Value::String(reason.to_string()),
    );
    EvidenceItem::new("reputation", HashMap::new(), outputs, HashMap::new())
}

fn build_evidence_result(sha256: &str, r: &CachedReputationResult) -> EvidenceItem {
    let mut inputs = HashMap::new();
    inputs.insert("sha256".to_string(), sha256.to_string());
    inputs.insert("source".to_string(), "VirusTotal v3".to_string());

    let mut outputs = HashMap::new();
    outputs.insert(
        "engines_total".to_string(),
        serde_json::Value::Number(serde_json::Number::from(r.engines_total)),
    );
    outputs.insert(
        "engines_detected".to_string(),
        serde_json::Value::Number(serde_json::Number::from(r.engines_detected)),
    );
    outputs.insert(
        "reputation_label".to_string(),
        serde_json::Value::String(r.reputation_label.clone()),
    );
    if let Some(ls) = &r.last_seen {
        outputs.insert(
            "last_seen".to_string(),
            serde_json::Value::String(ls.clone()),
        );
    }
    EvidenceItem::new("reputation", inputs, outputs, HashMap::new())
}
