/// Static inspection stage.
///
/// Examines the artifact without executing it:
/// - Detects file type via magic bytes + extension fallback.
/// - Extracts bounded printable strings.
/// - Scans for suspicious indicators: URLs, PowerShell keywords, base64 blobs.
/// - Computes Shannon entropy (sampled to avoid cost on huge files).
/// - Flags high-entropy (packed/encrypted) artifacts per policy threshold.
///
/// Reports findings as evidence items. Never guesses "this is malware";
/// only reports observable, measurable indicators.
use crate::config::Policy;
use crate::error::VeriError;
use crate::evidence::{EvidenceItem, InspectionResult};
use regex::Regex;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use tracing::info;

#[derive(Debug)]
pub struct InspectStageResult {
    pub result: InspectionResult,
    pub evidence: Vec<EvidenceItem>,
}

/// Run the inspection stage.
pub async fn run(artifact_path: &Path, policy: &Policy) -> Result<InspectStageResult, VeriError> {
    info!(stage = "inspect", path = %artifact_path.display(), "Starting static inspection");

    let bytes = read_sample(artifact_path, policy.entropy_sample_bytes)?;
    let all_bytes = std::fs::read(artifact_path).map_err(|e| VeriError::Io {
        path: artifact_path.display().to_string(),
        source: e,
    })?;

    let file_type = detect_file_type(&bytes, artifact_path);
    let is_executable = is_executable_type(&file_type);
    let is_script = is_script_type(&file_type);
    let entropy = shannon_entropy(&bytes);
    let entropy_flagged = entropy > policy.max_entropy_threshold;
    let strings_excerpt = extract_strings(
        &all_bytes,
        policy.min_string_length,
        policy.max_inspection_strings,
    );
    let indicators = find_indicators(&strings_excerpt);

    info!(
        stage = "inspect",
        file_type = %file_type,
        entropy = entropy,
        entropy_flagged = entropy_flagged,
        indicator_count = indicators.len(),
        "Inspection complete"
    );

    let result = InspectionResult {
        file_type: file_type.clone(),
        entropy,
        entropy_flagged,
        indicators: indicators.clone(),
        strings_excerpt: strings_excerpt.clone(),
        is_executable,
        is_script,
    };

    let evidence = build_evidence(
        artifact_path,
        &file_type,
        entropy,
        entropy_flagged,
        &indicators,
        &strings_excerpt,
    );

    Ok(InspectStageResult {
        result,
        evidence: vec![evidence],
    })
}

/// Detect file type using magic bytes with extension fallback.
fn detect_file_type(bytes: &[u8], path: &Path) -> String {
    // Magic byte signatures.
    if bytes.starts_with(b"\x7FELF") {
        return "ELF".to_string();
    }
    if bytes.starts_with(b"MZ") {
        return "PE".to_string();
    }
    if bytes.len() >= 4
        && (bytes.starts_with(b"\xfe\xed\xfa\xce")
            || bytes.starts_with(b"\xce\xfa\xed\xfe")
            || bytes.starts_with(b"\xfe\xed\xfa\xcf")
            || bytes.starts_with(b"\xcf\xfa\xed\xfe"))
    {
        return "Mach-O".to_string();
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return "ZIP".to_string();
    }
    if bytes.starts_with(b"\x1f\x8b") {
        return "GZIP".to_string();
    }
    if bytes.starts_with(b"BZh") {
        return "BZIP2".to_string();
    }
    if bytes.starts_with(b"\xfd7zXZ\x00") {
        return "XZ".to_string();
    }
    if bytes.starts_with(b"Rar!") {
        return "RAR".to_string();
    }
    if bytes.starts_with(b"%PDF") {
        return "PDF".to_string();
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "PNG".to_string();
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return "JPEG".to_string();
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return "GIF".to_string();
    }
    if bytes.starts_with(b"#!") {
        // Script shebang.
        let shebang: String = bytes.iter().take(64).map(|&b| b as char).collect();
        if shebang.contains("python") {
            return "Python Script".to_string();
        }
        if shebang.contains("bash") || shebang.contains("/sh") {
            return "Shell Script".to_string();
        }
        if shebang.contains("perl") {
            return "Perl Script".to_string();
        }
        if shebang.contains("ruby") {
            return "Ruby Script".to_string();
        }
        return "Script".to_string();
    }
    if bytes.starts_with(b"#!/usr/bin/env powershell")
        || bytes.starts_with(b"<#")
        || bytes.windows(12).any(|w| w == b"powershell -")
    {
        return "PowerShell Script".to_string();
    }
    // Debian package.
    if bytes.starts_with(b"!<arch>") {
        return "Debian Package".to_string();
    }
    // RPM.
    if bytes.starts_with(b"\xed\xab\xee\xdb") {
        return "RPM Package".to_string();
    }
    // WASM.
    if bytes.starts_with(b"\x00asm") {
        return "WebAssembly".to_string();
    }
    // Java class.
    if bytes.starts_with(b"\xca\xfe\xba\xbe") {
        return "Java Class".to_string();
    }
    // JAR (also a ZIP).
    if bytes.starts_with(b"PK") {
        return "ZIP/JAR".to_string();
    }
    // Fall back to extension.
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "sh" => "Shell Script",
        "py" => "Python Script",
        "ps1" | "psm1" | "psd1" => "PowerShell Script",
        "rb" => "Ruby Script",
        "pl" => "Perl Script",
        "js" | "mjs" => "JavaScript",
        "ts" => "TypeScript",
        "exe" | "dll" => "PE (by extension)",
        "so" => "ELF (by extension)",
        "dylib" => "Mach-O (by extension)",
        "jar" | "war" | "ear" => "JAR",
        "rpm" => "RPM Package",
        "deb" => "Debian Package",
        "tar" => "TAR Archive",
        "gz" => "GZIP",
        "bz2" => "BZIP2",
        "xz" => "XZ",
        "zip" => "ZIP",
        "7z" => "7-Zip Archive",
        "pdf" => "PDF",
        "txt" | "md" | "rst" => "Text",
        "yaml" | "yml" => "YAML",
        "json" => "JSON",
        "toml" => "TOML",
        "xml" => "XML",
        "wasm" => "WebAssembly",
        "asc" | "gpg" | "pgp" => "PGP Data",
        "" => "Unknown (no extension)",
        _ => "Unknown",
    }
    .to_string()
}

fn is_executable_type(file_type: &str) -> bool {
    matches!(
        file_type,
        "ELF"
            | "PE"
            | "Mach-O"
            | "ELF (by extension)"
            | "PE (by extension)"
            | "Mach-O (by extension)"
            | "WebAssembly"
            | "Java Class"
    )
}

fn is_script_type(file_type: &str) -> bool {
    file_type.contains("Script")
}

/// Compute Shannon entropy of byte slice (0.0 = uniform; 8.0 = random).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Extract printable ASCII/UTF-8 strings from binary data.
///
/// A string is a contiguous run of printable characters (0x20–0x7e or valid
/// UTF-8) of length >= `min_len`. Bounded to `max_count` results.
fn extract_strings(data: &[u8], min_len: usize, max_count: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = String::new();

    for &b in data {
        if results.len() >= max_count {
            break;
        }
        if (0x20..0x7f).contains(&b) {
            // Printable ASCII.
            current.push(b as char);
            if current.len() > 200 {
                // Bound individual string length.
                current.truncate(200);
                if current.len() >= min_len {
                    results.push(current.clone());
                }
                current.clear();
            }
        } else {
            if current.len() >= min_len {
                results.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= min_len && results.len() < max_count {
        results.push(current);
    }
    results
}

/// Scan extracted strings for suspicious indicators.
fn find_indicators(strings: &[String]) -> Vec<String> {
    let mut indicators = Vec::new();

    // URL pattern.
    let url_re = Regex::new(r#"https?://[^\s"'<>]{8,}"#).expect("url regex");
    // PowerShell dangerous keywords.
    let ps_keywords = [
        "Invoke-Expression",
        "IEX",
        "DownloadString",
        "DownloadFile",
        "FromBase64String",
        "EncodedCommand",
        "Invoke-Shellcode",
        "Invoke-Mimikatz",
        "Add-MpPreference",
        "Set-MpPreference",
        "DisableRealtimeMonitoring",
        "BypassExecutionPolicy",
        "Invoke-WebRequest",
        "Start-BitsTransfer",
        "Net.WebClient",
    ];
    // Shell patterns.
    let shell_keywords = [
        "curl -o",
        "wget -O",
        "chmod +x",
        "base64 -d",
        "bash -c",
        "sh -c",
        "/dev/tcp/",
        "nc -e",
        "mkfifo",
        "nohup",
        "crontab",
        "LD_PRELOAD",
    ];
    // Base64 blob heuristic: 64+ chars of base64 alphabet with optional padding.
    let b64_re = Regex::new(r"[A-Za-z0-9+/]{64,}={0,2}").expect("base64 regex");

    let mut found_urls = std::collections::HashSet::new();
    let mut found_ps = std::collections::HashSet::new();
    let mut found_shell = std::collections::HashSet::new();
    let mut found_b64 = 0usize;

    for s in strings {
        for mat in url_re.find_iter(s) {
            found_urls.insert(mat.as_str().to_string());
        }
        for kw in &ps_keywords {
            if s.contains(kw) {
                found_ps.insert(kw.to_string());
            }
        }
        for kw in &shell_keywords {
            if s.contains(kw) {
                found_shell.insert(kw.to_string());
            }
        }
        if b64_re.is_match(s) {
            found_b64 += 1;
        }
    }

    for url in found_urls.iter().take(10) {
        indicators.push(format!("URL: {}", url));
    }
    for kw in &found_ps {
        indicators.push(format!("PowerShell keyword: {}", kw));
    }
    for kw in &found_shell {
        indicators.push(format!("Shell pattern: {}", kw));
    }
    if found_b64 > 0 {
        indicators.push(format!("Possible base64 blobs: {} found", found_b64));
    }

    indicators
}

fn read_sample(path: &Path, max_bytes: usize) -> Result<Vec<u8>, VeriError> {
    let mut file = std::fs::File::open(path).map_err(|e| VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut buf = vec![0u8; max_bytes];
    let n = file.read(&mut buf).map_err(|e| VeriError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    buf.truncate(n);
    Ok(buf)
}

fn build_evidence(
    path: &Path,
    file_type: &str,
    entropy: f64,
    entropy_flagged: bool,
    indicators: &[String],
    strings_excerpt: &[String],
) -> EvidenceItem {
    let mut inputs = HashMap::new();
    inputs.insert("artifact_path".to_string(), path.display().to_string());

    let mut outputs = HashMap::new();
    outputs.insert(
        "file_type".to_string(),
        serde_json::Value::String(file_type.to_string()),
    );
    outputs.insert("entropy".to_string(), serde_json::json!(entropy));
    outputs.insert(
        "entropy_flagged".to_string(),
        serde_json::Value::Bool(entropy_flagged),
    );
    outputs.insert(
        "indicator_count".to_string(),
        serde_json::Value::Number(serde_json::Number::from(indicators.len() as u64)),
    );
    outputs.insert(
        "indicators".to_string(),
        serde_json::Value::Array(
            indicators
                .iter()
                .map(|i| serde_json::Value::String(i.clone()))
                .collect(),
        ),
    );
    // Include first 20 extracted strings as evidence.
    outputs.insert(
        "strings_sample".to_string(),
        serde_json::Value::Array(
            strings_excerpt
                .iter()
                .take(20)
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ),
    );

    EvidenceItem::new("inspect", inputs, outputs, HashMap::new())
}
