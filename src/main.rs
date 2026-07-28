/// veriscan — defense-grade software artifact verification CLI.
///
/// Entry point: parses CLI arguments, builds RunConfig, invokes the
/// orchestrator, writes reports, and exits with the correct exit code.
///
/// Exit codes:
///   0  VERIFIED
///   10 UNVERIFIED
///   20 FAILED
///   99 Tool error (policy invalid, I/O failure, etc.)
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use veriscan_lib::{
    config::{Policy, RunConfig},
    orchestrator, report,
    stages::bundle,
};

#[derive(Debug, Parser)]
#[command(
    name = "veriscan",
    version,
    author,
    about = "Defense-grade deterministic software artifact verification",
    long_about = "Verifies integrity, authenticity, and risk posture of software artifacts \
                  through a mandatory, ordered pipeline. Outputs JSON and Markdown reports.\n\n\
                  Exit codes: 0=VERIFIED, 10=UNVERIFIED, 20=FAILED, 99=tool error"
)]
struct Cli {
    /// Enable verbose/debug logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Emit structured JSON logs (for SIEM integration)
    #[arg(long, global = true)]
    json_logs: bool,

    /// Append audit log to this file
    #[arg(long, global = true, value_name = "FILE")]
    audit_log: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Verify an artifact (local file or URL)
    Verify {
        /// Artifact path or https:// URL
        source: String,

        /// Policy YAML file (default: embedded default policy)
        #[arg(short, long, value_name = "FILE")]
        policy: Option<PathBuf>,

        /// Verify an offline bundle directory instead of a file/URL
        #[arg(long, value_name = "BUNDLE_DIR")]
        offline: Option<PathBuf>,

        /// Expected SHA-256 checksum (hex)
        #[arg(long, value_name = "HEX")]
        expected_sha256: Option<String>,

        /// Expected SHA-512 checksum (hex)
        #[arg(long, value_name = "HEX")]
        expected_sha512: Option<String>,

        /// Directory of trusted PGP public keys (.asc files)
        #[arg(long, value_name = "DIR")]
        trusted_keys: Option<PathBuf>,

        /// Path to PGP detached signature file (.sig or .asc)
        #[arg(long, value_name = "FILE")]
        sig: Option<PathBuf>,

        /// Write JSON report to this file
        #[arg(long, value_name = "FILE")]
        report_json: Option<PathBuf>,

        /// Write Markdown report to this file
        #[arg(long, value_name = "FILE")]
        report_md: Option<PathBuf>,

        /// Print the full JSON report to stdout
        #[arg(long)]
        print_report: bool,
    },

    /// Create an offline verification bundle
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },

    /// Validate a policy YAML file
    PolicyValidate {
        /// Path to policy YAML
        policy: PathBuf,
    },

    /// Print the JSON report schema description
    ReportSchema,
}

#[derive(Debug, Subcommand)]
enum BundleAction {
    /// Create a new bundle from an artifact
    Create {
        /// Artifact to bundle
        #[arg(long, value_name = "FILE")]
        artifact: PathBuf,

        /// Directory containing trusted public keys and secret signing key
        #[arg(long, value_name = "DIR")]
        keys: PathBuf,

        /// Path to the secret signing key (within the keys directory)
        #[arg(long, value_name = "FILE")]
        signing_key: PathBuf,

        /// Output bundle directory
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialise tracing.
    let log_level = if cli.verbose { "debug" } else { "info" };
    if cli.json_logs {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(EnvFilter::new(log_level))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(log_level))
            .with_target(false)
            .init();
    }

    let exit_code = run(cli).await;
    process::exit(exit_code);
}

async fn run(cli: Cli) -> i32 {
    match cli.command {
        Commands::Verify {
            source,
            policy,
            offline,
            expected_sha256,
            expected_sha512,
            trusted_keys,
            sig,
            report_json,
            report_md,
            print_report,
        } => {
            // Load policy.
            let loaded_policy = match policy {
                Some(p) => match Policy::load(&p) {
                    Ok(pol) => pol,
                    Err(e) => {
                        error!(error = %e, "Failed to load policy");
                        return 99;
                    }
                },
                None => match Policy::default_policy() {
                    Ok(pol) => pol,
                    Err(e) => {
                        error!(error = %e, "Failed to load default policy");
                        return 99;
                    }
                },
            };

            let config = RunConfig {
                policy: loaded_policy,
                correlation_id: Uuid::new_v4().to_string(),
                offline_mode: offline.is_some(),
                report_json_path: report_json.clone(),
                report_md_path: report_md.clone(),
                audit_log_path: cli.audit_log.clone(),
                expected_sha256,
                expected_sha512,
                trusted_keys_dir: trusted_keys,
                detached_sig_path: sig,
            };

            // Determine if this is a bundle verify or file/URL verify.
            let json_report = if let Some(bundle_dir) = offline {
                match orchestrator::run_bundle_pipeline(&bundle_dir, &config).await {
                    Ok(r) => r,
                    Err(e) => {
                        error!(error = %e, "Bundle pipeline failed");
                        return 99;
                    }
                }
            } else {
                match orchestrator::run_pipeline(&source, &config).await {
                    Ok(r) => r,
                    Err(e) => {
                        error!(error = %e, "Verification pipeline failed");
                        return 99;
                    }
                }
            };

            // Print verdict summary.
            println!(
                "\n╔══════════════════════════════════════╗\n\
                 ║  VERDICT: {:^28} ║\n\
                 ╚══════════════════════════════════════╝\n",
                json_report.verdict.status
            );
            if let Some(reason) = &json_report.verdict.reason {
                println!("Reason: {}\n", reason);
            }
            println!(
                "SHA-256: {}",
                json_report.hashes.sha256.as_deref().unwrap_or("N/A")
            );
            println!("Signature: {}", json_report.signature.status);
            println!("Malware scan: {}", json_report.malware_scan.status);
            println!("Reputation: {}", json_report.reputation.status);
            println!("Exit code: {}\n", json_report.verdict.exit_code);

            // Write reports.
            if let Some(path) = &config.report_json_path {
                match report::write_json(&json_report, path) {
                    Ok(_) => info!(path = %path.display(), "JSON report written"),
                    Err(e) => error!(error = %e, "Failed to write JSON report"),
                }
            }
            if let Some(path) = &config.report_md_path {
                match report::write_markdown(&json_report, path) {
                    Ok(_) => info!(path = %path.display(), "Markdown report written"),
                    Err(e) => error!(error = %e, "Failed to write Markdown report"),
                }
            }
            if let Some(path) = &config.audit_log_path {
                match report::append_audit_jsonl(&json_report, path) {
                    Ok(_) => info!(path = %path.display(), "Audit record appended"),
                    Err(e) => error!(error = %e, "Failed to append audit record"),
                }
            }
            if print_report {
                match serde_json::to_string_pretty(&json_report) {
                    Ok(s) => println!("{}", s),
                    Err(e) => error!(error = %e, "Failed to serialise report"),
                }
            }

            json_report.verdict.exit_code
        }

        Commands::Bundle { action } => match action {
            BundleAction::Create {
                artifact,
                keys,
                signing_key,
                out,
            } => {
                info!(
                    artifact = %artifact.display(),
                    out = %out.display(),
                    "Creating bundle"
                );
                match bundle::create(&artifact, &keys, &out, &signing_key).await {
                    Ok(_) => {
                        println!("Bundle created at: {}", out.display());
                        0
                    }
                    Err(e) => {
                        error!(error = %e, "Bundle creation failed");
                        99
                    }
                }
            }
        },

        Commands::PolicyValidate { policy } => match Policy::load(&policy) {
            Ok(pol) => {
                println!("Policy '{}' v{} is valid.", pol.name, pol.version);
                println!("Digest: {}", pol.digest());
                0
            }
            Err(e) => {
                eprintln!("Policy validation failed: {}", e);
                99
            }
        },

        Commands::ReportSchema => {
            println!("{}", REPORT_SCHEMA_DESCRIPTION);
            0
        }
    }
}

const REPORT_SCHEMA_DESCRIPTION: &str = r#"veriscan JSON Report Schema (v1.0)
===================================

Top-level fields:
  schema_version   String   "1.0"
  run_id           String   UUID v4 correlation ID
  timestamp        String   ISO 8601 UTC
  elapsed_secs     Number   Wall-clock seconds for the run
  artifact         Object   { source, filename, size_bytes }
  verdict          Object   { status: "VERIFIED"|"UNVERIFIED"|"FAILED", reason?, exit_code }
  hashes           Object   { sha256, sha512, sha256_verified?, sha512_verified? }
  signature        Object   { status, signer_uid?, fingerprint?, detail? }
  malware_scan     Object   { status, engine?, engine_version?, detections[] }
  reputation       Object   { status, engines_total?, engines_detected?, source?, last_seen?, link? }
  inspection       Object   { file_type, entropy, entropy_flagged, indicators[], is_executable, is_script }
  policy           Object   { name, version, digest }
  decision_trace   Array    [ { rule_description, condition, matched, verdict? } ]
  evidence         Array    EvidenceItem[]
  tool_versions    Object   { tool_name: version_string }
  warnings         Array    String[]

EvidenceItem fields:
  timestamp          String   ISO 8601 UTC
  stage_name         String   Pipeline stage name
  inputs             Object   Named inputs to the stage
  outputs            Object   Named typed outputs from the stage
  tool_versions      Object   External tool versions used
  deterministic_id   String   SHA-256 of canonical evidence representation

Exit codes:
  0   VERIFIED
  10  UNVERIFIED
  20  FAILED
  99  Tool error
"#;
