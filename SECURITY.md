# Security Policy — veriscan

**Version:** 1.0
**Last updated:** 2026-02-25
**Maintained by:** veriscan project maintainers

---

## Table of Contents

1. [Security Policy Overview](#1-security-policy-overview)
2. [Supported Versions](#2-supported-versions)
3. [Vulnerability Reporting — Responsible Disclosure](#3-vulnerability-reporting--responsible-disclosure)
4. [Security Design Principles](#4-security-design-principles)
5. [Security Architecture Highlights](#5-security-architecture-highlights)
6. [Known Limitations](#6-known-limitations)
7. [Dependency Security Posture](#7-dependency-security-posture)

---

## 1. Security Policy Overview

veriscan is designed for use in regulated, high-assurance, and air-gapped environments where the integrity and authenticity of software artifacts must be verifiable before those artifacts are staged, deployed, or installed. Security is not an add-on feature of this project — it is the purpose of the project.

This document describes:

- Which versions receive security fixes.
- How to report a security vulnerability to the maintainers without public disclosure.
- The fundamental security design principles that every line of code in veriscan is required to uphold.
- The specific security controls implemented in the architecture.
- Known limitations that users must understand before relying on veriscan in a security-sensitive context.
- The security posture of third-party dependencies.

veriscan does **not** claim to be a complete security solution. It is one control layer in a defense-in-depth posture. Operators deploying veriscan in regulated environments must read and understand the limitations in Section 6 before using verification results to make production gating decisions.

---

## 2. Supported Versions

Only the most recent release of veriscan receives security fixes. There is no long-term support (LTS) track at this time.

| Version | Supported |
|---------|-----------|
| Latest release (0.1.x) | Yes — receives security fixes |
| Any prior release | No — upgrade required |

Because veriscan is intended for high-security environments, operators are expected to run from a known, pinned build and to verify the veriscan binary itself before deployment (using the same supply-chain verification practices the tool enforces).

---

## 3. Vulnerability Reporting — Responsible Disclosure

The maintainers take security vulnerabilities seriously. **Do not file public GitHub issues for security vulnerabilities.** Public disclosure before a fix is available puts all users at risk.

### Reporting Procedure

1. **Email the security contact** at the address listed in the repository's `SECURITY.md` contact field (or open a private security advisory via the GitHub repository's "Security" tab → "Report a vulnerability").
2. Include as much detail as possible:
   - The veriscan version affected.
   - A clear description of the vulnerability and its potential impact.
   - Steps to reproduce, or a proof-of-concept (kept private).
   - Your assessment of severity using CVSS v3.1 or plain English.
3. The maintainers will acknowledge receipt within **5 business days**.
4. The maintainers will provide an estimated remediation timeline within **15 business days**.
5. A coordinated disclosure date will be agreed upon. The default embargo period is **90 days** from initial report, following industry practice. Shorter embargo periods may be agreed upon for critical vulnerabilities.
6. Credit for the discovery will be given in the release notes and `CHANGELOG.md` unless the reporter requests anonymity.

### What to Report

Please report vulnerabilities in:

- The veriscan binary and library crate.
- The bundled policy files if they contain a design flaw that allows bypass of intended controls.
- The offline bundle creation or verification logic.
- Any code path that could allow an attacker to produce a false `VERIFIED` verdict for a malicious artifact.

### What is Out of Scope

The following are not accepted as security vulnerabilities:

- Denial-of-service against the veriscan CLI when the operator supplies a pathologically large artifact (resource consumption by design).
- Theoretical attacks that require the attacker to already control the signing key (key compromise is outside the trust model).
- ClamAV or VirusTotal accuracy gaps (these are third-party tools; report issues to their respective projects).
- False positives (artifacts incorrectly flagged as bad).

---

## 4. Security Design Principles

The following principles are not aspirational — they are enforced in code. Any pull request that violates these principles will be rejected.

### 4.1 Artifacts Are Never Executed

veriscan reads artifact bytes for cryptographic operations and static analysis. It **never** executes, interprets, or loads the artifact under examination. There is no dynamic loading, no sandboxed execution, no WASM runtime, and no script interpreter. This is a hard invariant.

Rationale: executing an untrusted artifact for the purpose of analyzing it would expose the analysis host to exactly the attack the tool is designed to prevent.

### 4.2 Fail-Closed — Not Fail-Open

All pipeline stages default to a restrictive outcome when they encounter an unexpected condition. An error in any stage produces `UNVERIFIED` (exit code 10) or `FAILED` (exit code 20) — never a silent pass. The policy can escalate `UNVERIFIED` to `FAILED` for required checks (e.g., `malware_failure_is_fatal: true`).

There is no configuration option that causes veriscan to return `VERIFIED` when a check cannot be completed. Partial verification is always visible in the exit code and report.

### 4.3 No Boolean Trust — Typed Verdicts

Trust is never represented as a boolean (`true`/`false`) in the public API or report schema. The `VerificationStatus` type is an enum with three distinct, non-interchangeable variants:

```
Verified
Unverified { reason, evidence }
Failed     { reason, evidence }
```

This prevents accidental promotion of `Unverified` to a passing state through logical inversion or comparison with `true`. Callers must handle all three variants explicitly at the type level.

### 4.4 No Secrets in Logs

API keys, environment variable values, and any other credential material are **never logged**. The VirusTotal API key is read from an environment variable named in the policy file, but the key value itself is only passed as an HTTP header and is never written to structured log output, reports, or evidence items.

The tracing subsystem is configured to emit structured JSON logs. Field values are validated before emission. No `format!` macro that could concatenate a secret value into a log message is permitted in security-critical code paths.

### 4.5 Pipeline Ordering Is Not User-Controllable

The seven-stage pipeline (`Acquire → Hash → Signature → Malware → Inspect → Reputation → Policy`) is enforced by the orchestrator. No CLI flag, environment variable, or policy setting can reorder, skip, or short-circuit a stage. Policy controls the *behavior* of stages (e.g., whether a missing signature is `UNVERIFIED` or `FAILED`); it cannot remove stages from the pipeline.

### 4.6 Artifact Integrity Is Verified Between Stages

After the hash, signature, malware, and inspect stages — the stages that read artifact content — the orchestrator re-computes the SHA-256 of the artifact on disk and compares it to the hash recorded at acquisition time. Any mutation detected between stages aborts the run with a pipeline error carrying error code `ERR_ARTIFACT_MUTATED`: the process exits with code 99 and no report is emitted. This detects TOCTOU (time-of-check/time-of-use) attacks where a compromised staging area could swap the artifact after the hash check.

### 4.7 Policy Is Auditable and Deterministic

Every policy document has a SHA-256 digest computed from its canonical JSON serialization. The digest is included in every report. Auditors can reproduce the digest from the policy YAML and confirm that the exact policy used for a given run is on record.

---

## 5. Security Architecture Highlights

### 5.1 Pure-Rust Cryptography — No System C Library Required

PGP signature verification uses [`sequoia-openpgp`](https://crates.io/crates/sequoia-openpgp) compiled with the `crypto-rust` feature flag, which uses pure-Rust cryptographic backends (`RustCrypto`). This eliminates the dependency on system OpenSSL or GnuPG for cryptographic operations and reduces the attack surface from native C library vulnerabilities.

Hash computation uses [`sha2`](https://crates.io/crates/sha2) from the RustCrypto project, which has been independently audited.

```toml
# Cargo.toml — pure-Rust crypto backend
sequoia-openpgp = { version = "1", default-features = false, features = ["crypto-rust", "allow-experimental-crypto", "allow-variable-time-crypto"] }
sha2 = "0.10"
```

The `allow-experimental-crypto` flag is the required opt-in for the RustCrypto backend. The `allow-variable-time-crypto` flag is required because RustCrypto does not provide constant-time operations; this is acceptable for veriscan's non-interactive batch verification workload, where timing side-channels against a live user are not a concern.

The release build profile enables link-time optimization (`lto = true`) and single codegen unit (`codegen-units = 1`) to maximize compiler visibility into the full binary and strip dead code and unnecessary symbols (`strip = true`).

### 5.2 Subprocess Isolation for External Tool Invocations

When invoking ClamAV (`clamscan`), veriscan uses a hardened subprocess wrapper with the following properties:

| Control | Implementation |
|---------|---------------|
| Absolute binary path required | `SubprocessPathNotAbsolute` error if path is relative |
| Environment completely cleared | `Command::env_clear()` — no inherited secrets |
| No shell interpretation | Arguments passed directly via `execvp`, not `sh -c` |
| Output bounded | `max_subprocess_output_bytes` cap on stdout and stderr |
| Hard timeout | `tokio::time::timeout` kills process after configured seconds |
| Stdin closed | `Stdio::null()` — no interactive input |
| Process killed on drop | `kill_on_drop(true)` — no orphan processes |

```rust
// src/util/command.rs
cmd.args(args)
    .env_clear()                          // no secret leakage
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .stdin(std::process::Stdio::null())
    .kill_on_drop(true);
```

### 5.3 Path Traversal Prevention

Bundle-relative paths taken from manifest entries — the only paths derived from untrusted input — are validated by the `safe_bundle_path` function in `src/stages/bundle.rs` before use. The function applies a lexical pre-check that rejects absolute paths and any path containing `..`, then canonicalizes both the bundle root and the joined path (resolving symlinks and relative segments) and requires the resolved path to remain contained under the canonicalized bundle root. Other CLI-supplied paths (artifact, policy, key, and report paths) are provided directly by the operator and used as given.

```rust
// src/stages/bundle.rs — bundle manifest path validation
fn safe_bundle_path(base: &Path, relative: &str) -> Result<PathBuf, VeriError> {
    // Fast lexical pre-check — catches the common cases early.
    if relative.starts_with('/') || relative.contains("..") {
        return Err(VeriError::PathTraversal { path: relative.to_string() });
    }

    // Canonical base: must exist or we cannot safely confine.
    let base_abs = base.canonicalize()?;
    let joined = base_abs.join(relative);

    // Canonicalize the joined path (resolves symlinks, normalizes segments).
    let resolved = if joined.exists() { joined.canonicalize()? } else { joined.clone() };

    if !resolved.starts_with(&base_abs) {
        return Err(VeriError::PathTraversal { path: relative.to_string() });
    }
    Ok(resolved)
}
```

A malicious bundle manifest that lists `../../etc/passwd` as a file path — or that attempts to escape the bundle directory through a symlink — will be rejected before any file operations are performed.

### 5.4 Secret Redaction in Evidence

Evidence items record the *names* of environment variables used (e.g., `VT_API_KEY`) and the *names* of key files loaded, but never their values. The VirusTotal API key is read from the environment immediately before use and passed directly to the HTTP client without being stored in any struct, logged, or serialized. Evidence items include the hash submitted to VirusTotal (the artifact SHA-256) but never the API key.

### 5.5 Signer Fingerprint Pinning

When `allow_signers` is non-empty in the policy, signature verification is not complete until the verified signer's fingerprint appears in the allow list. A valid signature from an unknown key is rejected with `SignerNotAllowed` (FAILED). This prevents an adversary with a freshly-generated PGP key from producing a technically-valid signature that passes the cryptographic check but should not be trusted.

```yaml
# contractor_strict.yaml
allow_signers:
  - "AABBCCDD..."   # Full 40-hex PGP v4 fingerprint or 64-hex v5 fingerprint
```

The policy validator (`Policy::validate()`) checks that each entry in `allow_signers` is either a 40-character (PGP v4) or 64-character (PGP v5) hex string with no non-hex characters. Malformed fingerprints are rejected at policy load time, before any verification runs.

### 5.6 Offline Bundle Chain of Custody

For air-gapped environments, the offline bundle provides a cryptographically-sealed chain of custody:

1. The bundle manifest (`bundle.manifest.json`) lists every file in the bundle with its SHA-256 digest.
2. The manifest is PGP-signed (`bundle.manifest.sig`).
3. On verification: the manifest signature is checked **first** — before the manifest is parsed or any file hash is read.
4. Only after the manifest signature is verified are individual file hashes trusted.
5. Each file's SHA-256 is checked against the manifest entry.
6. The artifact's PGP signature is then verified.
7. The full pipeline runs on the verified artifact.

No file in the bundle is trusted until the manifest signature passes. A tampered manifest will cause the verification to fail at step 3 before any potentially attacker-controlled content is processed.

### 5.7 Atomic Report Writes

All report files are written atomically using a temporary file in the same directory followed by a rename (POSIX `rename(2)` is atomic). This prevents a reader from observing a partially-written report. The `write_bytes_atomic` utility in `src/util/fs.rs` implements this pattern.

---

## 6. Known Limitations

Operators must understand the following limitations before making production gating decisions based on veriscan output.

| Limitation | Description |
|------------|-------------|
| **Zero-day malware** | ClamAV relies on signature databases. Novel malware with no signatures will not be detected. There is no behavioral or heuristic detection beyond static string indicators. |
| **Signed malicious releases** | If an upstream vendor's signing key is compromised, veriscan cannot detect that a signed artifact is malicious unless it appears in the ClamAV or VirusTotal databases. Verified != safe. |
| **Insider threat** | An insider with legitimate access to signing infrastructure can produce correctly signed malicious artifacts that veriscan will pass. Key management and code review controls are outside veriscan's scope. |
| **Malicious compilers / toolchains** | veriscan inspects artifact bytes statically. A supply-chain attack at the compiler or build system level (e.g., Ken Thompson's "Trusting Trust" attack) is not detectable unless the resulting binary matches a known-bad signature. |
| **VirusTotal data freshness** | The reputation check returns data from VirusTotal's last analysis. A recently-weaponized artifact may not yet be flagged. The cache TTL (default 24 hours) means a hash that was clean yesterday may be stale. |
| **Hash algorithm agility** | veriscan computes SHA-256 and SHA-512. It does not currently support SHA-3 or BLAKE3. If SHA-256 becomes cryptographically weak, updates will be required. |
| **No runtime behavioral analysis** | veriscan performs static inspection only. Artifacts that execute benign code initially and download a payload later are not detectable. |
| **No SBOM enforcement (Phase II)** | The `require_sbom` policy flag currently produces `UNVERIFIED` rather than `FAILED`. SBOM verification is a planned feature. |
| **ClamAV database currency** | The detection quality of the malware scan depends on the freshness of the ClamAV signature database on the host. veriscan does not update ClamAV databases. |
| **PGP Web of Trust** | veriscan uses key pinning (`allow_signers`), not the PGP web of trust. If `allow_signers` is empty, any valid PGP signature from any key is accepted. Operators should always populate `allow_signers` in high-assurance policies. |

---

## 7. Dependency Security Posture

veriscan's dependencies are chosen for minimal attack surface, active maintenance, and where possible, independent security audits.

| Crate | Version | Purpose | Security Notes |
|-------|---------|---------|----------------|
| `sequoia-openpgp` | 1.x | PGP verification | Pure-Rust crypto backend; no C FFI for crypto ops; maintained by Sequoia-PGP project |
| `sha2` | 0.10 | SHA-256/512 | RustCrypto project; independently audited |
| `clap` | 4.5 | CLI parsing | No unsafe code in argument parsing path |
| `serde` / `serde_json` / `serde_yaml` | latest | Serialization | Widely used; well-audited |
| `reqwest` | 0.12 | HTTP client | TLS via `rustls` or platform native; does not upload artifacts |
| `tokio` | 1.x | Async runtime | Production-grade; no cryptographic operations |
| `regex` | 1.11 | Pattern matching | ReDoS protection built-in; bounded input |
| `uuid` | 1.10 | Correlation IDs | No security-sensitive operations |
| `tracing` | 0.1 | Structured logging | No secret emission by design |
| `thiserror` / `anyhow` | latest | Error handling | No unsafe code |
| `walkdir` | 2.5 | Directory traversal | Bounded depth; `follow_links: false` |
| `tempfile` | 3.12 | Atomic writes | Secure temp file creation |
| `chrono` | 0.4 | Timestamps | No security operations |
| `hex` | 0.4 | Hash encoding | Simple encoding; no cryptographic operations |

### Dependency Update Policy

- All dependencies are pinned to a minimum minor version in `Cargo.toml`.
- `Cargo.lock` is committed to the repository for binary builds to ensure reproducible builds.
- The dependency tree is reviewed with `cargo audit` against the RustSec advisory database as part of the release process. No hosted CI configuration is bundled with the repository.
- Any dependency with a published RUSTSEC advisory affecting veriscan's usage will be updated or mitigated within **14 days** of advisory publication for high/critical severity, and **60 days** for low/medium.

### Supply Chain Integrity of veriscan Itself

Operators building veriscan from source should:

1. Verify the source archive or git commit against the published PGP signature from the maintainers.
2. Use `cargo build --release` with a pinned Rust toolchain version.
3. Verify the produced binary's SHA-256 against the published checksum before deployment.
4. Consider using veriscan itself to verify veriscan distributions (bootstrap trust from a known-good build).

---

*This security policy is reviewed and updated with each release. For questions not covered here, open a non-sensitive discussion in the repository or contact the maintainers directly.*
