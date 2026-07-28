/// Error-case coverage tests.
///
/// Each test exercises a specific error variant to confirm:
/// 1. The right error is returned (not a panic, not a different error).
/// 2. The error code is the expected stable string.
///
/// This file complements pipeline_invariants.rs and policy_decisions.rs by
/// covering paths that the happy-path tests intentionally skip.
use veriscan_lib::{
    config::Policy,
    error::VeriError,
    stages::acquire,
    util::{command::run_safe, net::check_url_allowed},
};

fn default_policy() -> Policy {
    Policy::default_policy().expect("default policy")
}

// ── Acquire stage ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_acquire_url_denied_by_policy_when_network_off() {
    let mut policy = default_policy();
    policy.allow_network = false;

    let err = acquire::run("https://example.com/artifact.tar.gz", &policy)
        .await
        .expect_err("Should fail when network disabled");

    assert!(
        matches!(err, VeriError::NetworkDeniedByPolicy),
        "Expected NetworkDeniedByPolicy, got: {}",
        err
    );
    assert_eq!(err.code(), "ERR_NETWORK_POLICY");
}

#[tokio::test]
async fn test_acquire_http_url_denied_by_policy_when_network_off() {
    let mut policy = default_policy();
    policy.allow_network = false;

    let err = acquire::run("http://insecure.example.com/file.bin", &policy)
        .await
        .expect_err("Should fail on plain http with network disabled");

    assert!(
        matches!(err, VeriError::NetworkDeniedByPolicy),
        "Expected NetworkDeniedByPolicy, got: {}",
        err
    );
}

#[tokio::test]
async fn test_acquire_nonexistent_local_path_returns_artifact_not_found() {
    let policy = default_policy();
    let nonexistent = "/tmp/veriscan_test_does_not_exist_xyz987.bin";

    let err = acquire::run(nonexistent, &policy)
        .await
        .expect_err("Should fail for nonexistent path");

    assert!(
        matches!(err, VeriError::ArtifactNotFound { .. }),
        "Expected ArtifactNotFound, got: {}",
        err
    );
    assert_eq!(err.code(), "ERR_ARTIFACT_NOT_FOUND");
}

#[tokio::test]
async fn test_acquire_existing_local_path_succeeds() {
    use std::io::Write;
    let policy = default_policy();
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(b"test artifact data").expect("write");

    let result = acquire::run(f.path().to_str().unwrap(), &policy)
        .await
        .expect("Acquire of existing file must succeed");

    assert_eq!(result.size_bytes, 18);
    assert!(!result.sha256_at_acquire.is_empty());
}

// ── URL denylist (net utility) ────────────────────────────────────────────────

#[test]
fn test_check_url_allowed_blocks_denied_pattern() {
    let denylist = vec![
        "malware.example.com".to_string(),
        "pastebin.com".to_string(),
    ];

    let err = check_url_allowed("https://malware.example.com/payload.sh", &denylist)
        .expect_err("Should be denied by denylist");

    assert!(
        matches!(err, VeriError::UrlDenied { .. }),
        "Expected UrlDenied, got: {}",
        err
    );
    assert_eq!(err.code(), "ERR_URL_DENIED");
}

#[test]
fn test_check_url_allowed_blocks_second_pattern_in_list() {
    let denylist = vec![
        "innocent.example.com".to_string(),
        "pastebin.com".to_string(),
    ];

    let err = check_url_allowed("https://pastebin.com/raw/abc123", &denylist)
        .expect_err("Should be denied by second pattern");

    assert!(matches!(err, VeriError::UrlDenied { .. }));
}

#[test]
fn test_check_url_allowed_passes_clean_url() {
    let denylist = vec![
        "malware.example.com".to_string(),
        "pastebin.com".to_string(),
    ];

    check_url_allowed(
        "https://releases.example.com/v1.0.0/artifact.tar.gz",
        &denylist,
    )
    .expect("Clean URL must be allowed");
}

#[test]
fn test_check_url_allowed_empty_denylist_always_passes() {
    check_url_allowed("https://any.url.example.com/file.bin", &[])
        .expect("Empty denylist must allow any URL");
}

// ── Safe subprocess wrapper ───────────────────────────────────────────────────

#[tokio::test]
async fn test_run_safe_rejects_relative_binary_path() {
    use std::path::Path;

    let err = run_safe(Path::new("bin/clamscan"), &[], 5, 4096)
        .await
        .expect_err("Relative path must be rejected");

    assert!(
        matches!(err, VeriError::SubprocessPathNotAbsolute { .. }),
        "Expected SubprocessPathNotAbsolute, got: {}",
        err
    );
    assert_eq!(err.code(), "ERR_SUBPROCESS_PATH");
}

#[tokio::test]
async fn test_run_safe_rejects_bare_binary_name() {
    use std::path::Path;

    let err = run_safe(Path::new("clamscan"), &[], 5, 4096)
        .await
        .expect_err("Bare name must be rejected (no PATH lookup)");

    assert!(
        matches!(err, VeriError::SubprocessPathNotAbsolute { .. }),
        "Expected SubprocessPathNotAbsolute, got: {}",
        err
    );
}

#[tokio::test]
async fn test_run_safe_absolute_nonexistent_returns_io_error() {
    use std::path::Path;

    // Absolute path that doesn't exist → Io error from spawn, not our guard.
    let result = run_safe(Path::new("/nonexistent/binary_xyz987"), &[], 5, 4096).await;
    assert!(result.is_err(), "Nonexistent binary must produce an error");
    // Passes the absolute-path guard, fails at spawn → Io error
    assert!(
        matches!(result.unwrap_err(), VeriError::Io { .. }),
        "Should be an Io error from the spawn attempt"
    );
}

// ── Error code stability ──────────────────────────────────────────────────────

#[test]
fn test_error_codes_are_stable_and_non_empty() {
    use std::io;

    let cases: Vec<(&str, VeriError)> = vec![
        (
            "ERR_IO",
            VeriError::Io {
                path: "/tmp/x".to_string(),
                source: io::Error::new(io::ErrorKind::NotFound, "not found"),
            },
        ),
        (
            "ERR_PATH_TRAVERSAL",
            VeriError::PathTraversal {
                path: "../x".to_string(),
            },
        ),
        (
            "ERR_ARTIFACT_NOT_FOUND",
            VeriError::ArtifactNotFound {
                path: "/tmp/nope".to_string(),
            },
        ),
        ("ERR_NETWORK_POLICY", VeriError::NetworkDeniedByPolicy),
        (
            "ERR_URL_DENIED",
            VeriError::UrlDenied {
                url: "https://bad.com".to_string(),
            },
        ),
        (
            "ERR_HASH_MISMATCH",
            VeriError::HashMismatch {
                expected: "abc".to_string(),
                actual: "def".to_string(),
            },
        ),
        (
            "ERR_ARTIFACT_MUTATED",
            VeriError::ArtifactMutated {
                before: "aaa".to_string(),
                after: "bbb".to_string(),
            },
        ),
        (
            "ERR_SIG_INVALID",
            VeriError::SignatureInvalid {
                reason: "bad".to_string(),
            },
        ),
        (
            "ERR_KEY_PARSE",
            VeriError::KeyParseError {
                reason: "bad key".to_string(),
            },
        ),
        (
            "ERR_BUNDLE_FILE_MISMATCH",
            VeriError::BundleFileMismatch {
                file: "x".to_string(),
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
        ),
        (
            "ERR_BUNDLE_FILE_MISSING",
            VeriError::BundleFileMissing {
                file: "x".to_string(),
            },
        ),
        (
            "ERR_BUNDLE_NOT_FOUND",
            VeriError::BundleNotFound {
                path: "/tmp/b".to_string(),
            },
        ),
        (
            "ERR_MANIFEST_PARSE",
            VeriError::ManifestParseError {
                reason: "parse fail".to_string(),
            },
        ),
        (
            "ERR_SUBPROCESS_PATH",
            VeriError::SubprocessPathNotAbsolute {
                path: "rel".to_string(),
            },
        ),
        ("ERR_INTERNAL", VeriError::Internal("oops".to_string())),
    ];

    for (expected_code, err) in cases {
        assert_eq!(
            err.code(),
            expected_code,
            "Stable code mismatch for variant: {}",
            err
        );
        assert!(!err.code().is_empty(), "Error code must not be empty");
    }
}
