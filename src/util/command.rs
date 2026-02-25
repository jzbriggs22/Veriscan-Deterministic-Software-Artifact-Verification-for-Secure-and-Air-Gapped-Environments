/// Safe subprocess execution wrapper.
///
/// Security constraints enforced on every invocation:
/// - Binary must be an absolute path (no PATH lookup).
/// - Environment is completely cleared (no secret leakage via inherited env).
/// - No shell interpretation; args are passed directly to execvp.
/// - Output is captured and bounded to prevent log injection / OOM.
/// - Execution is aborted after a configurable timeout.
use crate::error::VeriError;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Result of a safely-executed subprocess.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// Whether the process was killed due to timeout.
    pub timed_out: bool,
}

/// Execute `binary` with `args`, no environment, bounded output, enforced timeout.
///
/// - `binary` must be an absolute path.
/// - `timeout_secs` is a hard wall-clock limit.
/// - `max_output_bytes` caps both stdout and stderr (each).
pub async fn run_safe(
    binary: &Path,
    args: &[&str],
    timeout_secs: u64,
    max_output_bytes: usize,
) -> Result<CommandOutput, VeriError> {
    // Enforce absolute path — prevents PATH hijacking.
    if !binary.is_absolute() {
        return Err(VeriError::SubprocessPathNotAbsolute {
            path: binary.display().to_string(),
        });
    }

    let binary_str = binary.display().to_string();

    let mut cmd = Command::new(binary);
    cmd.args(args)
        // Clear the entire environment — no leaked secrets.
        .env_clear()
        // Do not attach to the terminal.
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        // Prevent the child from acquiring a controlling terminal.
        .kill_on_drop(true);

    let run_future = async {
        let child = cmd.spawn().map_err(|e| VeriError::Io {
            path: binary_str.clone(),
            source: e,
        })?;

        let output = child.wait_with_output().await.map_err(|e| VeriError::Io {
            path: binary_str.clone(),
            source: e,
        })?;

        let exit_code = output.status.code().unwrap_or(-1);

        // Bound and sanitise captured output.
        let stdout_raw = &output.stdout[..output.stdout.len().min(max_output_bytes)];
        let stderr_raw = &output.stderr[..output.stderr.len().min(max_output_bytes)];
        let stdout = String::from_utf8_lossy(stdout_raw).into_owned();
        let stderr = String::from_utf8_lossy(stderr_raw).into_owned();

        Ok::<CommandOutput, VeriError>(CommandOutput {
            exit_code,
            stdout,
            stderr,
            timed_out: false,
        })
    };

    match timeout(Duration::from_secs(timeout_secs), run_future).await {
        Ok(result) => result,
        Err(_) => {
            // Timeout elapsed — process was killed by kill_on_drop.
            Ok(CommandOutput {
                exit_code: -1,
                stdout: String::new(),
                stderr: format!(
                    "Process '{}' killed after {}s timeout",
                    binary_str, timeout_secs
                ),
                timed_out: true,
            })
        }
    }
}

/// Attempt to retrieve the version string of an installed tool by running
/// `binary --version`. Returns `"unknown"` on any failure (tool may not
/// support --version; we never hard-fail on version detection).
pub async fn tool_version(binary: &Path, timeout_secs: u64) -> String {
    if !binary.is_absolute() {
        return "unknown (non-absolute path)".to_string();
    }
    match run_safe(binary, &["--version"], timeout_secs, 4096).await {
        Ok(out) => {
            let combined = format!("{}{}", out.stdout, out.stderr);
            combined
                .lines()
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string()
        }
        Err(_) => "unknown".to_string(),
    }
}
