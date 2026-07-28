# Veriscan Architecture

## Overview

Veriscan is a Rust CLI tool that verifies software artifacts through a mandatory, ordered, seven-stage pipeline. The design prioritizes auditability, determinism, and fail-closed behavior over convenience. Every architectural decision can be traced to a security requirement.

The tool is structured as a library crate (`veriscan_lib`) with a thin binary entry point (`src/main.rs`). The library exposes a clean API that can be consumed by test harnesses, future language bindings, or integration wrappers.

---

## Module Responsibilities

### `src/main.rs` — CLI Entry Point

Parses CLI arguments using `clap`'s derive API. Loads the policy, constructs a `RunConfig`, and dispatches to either `orchestrator::run_pipeline` (file/URL verification) or `orchestrator::run_bundle_pipeline` (offline bundle verification). Writes reports and exits with the correct exit code.

Responsibilities:
- CLI argument parsing and validation
- Logging initialization (human-readable or JSON structured logs)
- Policy file loading
- Report writing (JSON + Markdown)
- Process exit with deterministic exit codes (0 / 10 / 20 / 99)

### `src/lib.rs` — Library Root

Re-exports the public API surface for test harnesses and future consumers. Declares all modules.

### `src/error.rs` — Error Hierarchy

Defines `VeriError`, a typed error enum covering every failure mode: I/O, network, hash mismatch, signature failure, bundle errors, malware scan errors, reputation errors, policy errors, and subprocess errors.

Key design decisions:
- Every variant carries context (e.g., `HashMismatch` carries both `expected` and `actual` values).
- Each variant maps to a stable machine-readable error code (e.g., `ERR_HASH_MISMATCH`) for use in evidence records.
- No information is collapsed into generic errors.

### `src/evidence.rs` — Evidence Model

Defines the `EvidenceItem` struct and `EvidenceBuilder` fluent API. Also defines the core domain types:

- `VerificationStatus` — typed enum with three variants: `Verified`, `Unverified { reason, evidence }`, `Failed { reason, evidence }`. Exit codes are computed from this enum at the type level.
- `PipelineResults` — accumulator for all stage outputs, passed to the policy stage.
- `SignatureResult`, `MalwareResult`, `InspectionResult`, `ReputationResult` — typed per-stage outcome enums.

The `EvidenceItem::new()` constructor computes the `deterministic_id` by constructing a canonical string (stage name + timestamp + sorted inputs + sorted outputs), hashing it with SHA-256, and hex-encoding the result. Because the timestamp is part of the canonical form, the ID differs across runs; it uniquely identifies an evidence item within a run and can be independently reproduced from the recorded fields, making post-generation tampering detectable.

### `src/config.rs` — Policy and Runtime Configuration

Defines:
- `Policy` — deserialized YAML policy structure with all configurable verification parameters.
- `RunConfig` — runtime configuration combining the loaded policy with CLI-supplied overrides (expected hashes, trusted key paths, report paths).
- `DecisionRule`, `RuleCondition`, `RuleVerdict` — the typed policy decision matrix DSL.
- `ExecutableHandling` — enum encoding the three executable handling modes (`allow`, `block_unsigned`, `deny_all`).

`Policy::digest()` computes the SHA-256 of the JSON-serialized policy, providing a fingerprint included in every report so auditors can verify the exact policy in effect.

### `src/orchestrator.rs` — Pipeline Orchestrator

The orchestrator is the sole authority on stage sequencing. It calls each stage in fixed order and enforces inter-stage invariants:

1. Calls `acquire::run()` → receives artifact path and initial SHA-256.
2. Calls `hash::run()` → returns computed hashes and match status.
3. Calls `assert_no_mutation()` → verifies artifact SHA-256 has not changed since acquire.
4. Calls `signature::run()`.
5. Calls `assert_no_mutation()`.
6. Calls `malware::run()`.
7. Calls `assert_no_mutation()`.
8. Calls `inspect::run()`.
9. Calls `assert_no_mutation()`.
10. Calls `reputation::run()`.
11. Calls `policy_stage::evaluate()`.
12. Assembles `JsonReport` from all collected results and evidence.

The `run_bundle_pipeline()` function first calls `bundle::verify()` to validate the bundle's manifest signature and all file hashes, then calls `run_pipeline()` in offline mode on the verified artifact path.

Early pipeline failures (e.g., hash mismatch in stage 2) cause `build_failed_report()` to be called, which constructs a FAILED report with the collected evidence and returns it rather than propagating an error that would produce exit code 99.

### `src/stages/acquire.rs` — Acquire Stage

Handles artifact acquisition from either a local file path or an HTTPS URL. For URL sources:
- Validates the URL against the policy denylist before any network activity.
- Emits a warning (not error) for plain HTTP URLs.
- Downloads to a named temporary file via `reqwest`; the temp file is held alive in `AcquireResult._temp_file` until the pipeline completes.

Records an `EvidenceItem` with: source, local path, size bytes, SHA-256 at acquisition, source type (local/url).

### `src/stages/hash.rs` — Hash Stage

Computes SHA-256 and SHA-512 in a single streaming pass (64 KiB buffer) to avoid reading the file twice. Resolves expected checksums in priority order:
1. Explicit CLI argument (`--expected-sha256` / `--expected-sha512`).
2. Adjacent checksum file (`<artifact>.sha256`, `<artifact>.SHA256`, `<artifact>.sha256sum`).
3. If `require_checksums: true` and no source found, returns a hard error.

A mismatch between computed and expected checksum returns `VeriError::HashMismatch`, which the orchestrator catches and converts to a FAILED report.

### `src/stages/signature.rs` — Signature Stage

Performs PGP detached signature verification using `sequoia-openpgp` with the `crypto-rust` feature (pure Rust, no C library). Supports armored (`.asc`) and binary (`.sig` / `.pgp` / `.gpg`) formats.

Locates the signature file at: explicit `--sig` path, then `<artifact>.sig`, then `<artifact>.asc`.

Loads trusted public keys from: explicit `--trusted-keys` directory, then a `trusted_keys/` directory adjacent to the artifact, searching up to depth 2.

When `allow_signers` is non-empty, the verified signer's fingerprint must appear in the list; otherwise `SignatureResult::SignerNotAllowed` is returned.

Returns one of: `Verified { signer_uid, fingerprint }`, `Missing`, `Invalid { reason }`, `SignerNotAllowed { fingerprint }`, `NotChecked`.

### `src/stages/malware.rs` — Malware Stage

Invokes `clamscan` via the `util::command::run_safe()` wrapper:
- Binary must be an absolute path (rejects relative paths to prevent PATH injection).
- Subprocess environment is completely cleared.
- stdout and stderr are bounded to `max_subprocess_output_bytes`.
- Execution is bounded by `subprocess_timeout_seconds`.

Interprets ClamAV exit codes: 0 = clean, 1 = virus found, 2+ = scan error. Parses detection names from lines ending in `FOUND`.

If `clamscan` is not found at the configured or default path, returns `MalwareResult::ToolMissing` (not an error; the policy stage decides whether this is UNVERIFIED or FAILED).

### `src/stages/inspect.rs` — Static Inspection Stage

Performs static analysis without executing the artifact:
- **File type detection:** Magic byte signatures for ELF, PE, Mach-O, ZIP, GZIP, BZIP2, XZ, RAR, PDF, PNG, JPEG, GIF, shebang scripts, Debian packages, RPM, WebAssembly, Java class files. Falls back to file extension.
- **Shannon entropy computation:** Computed over a configurable sample (default: 1 MiB). Values above `max_entropy_threshold` (default: 7.5 bits) set `entropy_flagged = true`.
- **String extraction:** Printable ASCII runs of `>= min_string_length` characters, bounded to `max_inspection_strings` results.
- **Indicator scanning:** Regex-based detection of HTTP/HTTPS URLs, PowerShell dangerous keywords (`Invoke-Expression`, `IEX`, `DownloadString`, etc.), shell injection patterns (`curl -o`, `chmod +x`, `/dev/tcp/`, etc.), and large base64 blobs.

### `src/stages/reputation.rs` — Reputation Stage

Performs a VirusTotal v3 hash-only lookup. The artifact bytes are never uploaded. The API key is read exclusively from the environment variable named by `policy.vt_api_key_env` (default: `VT_API_KEY`); it is never stored, never logged, and never included in reports.

Results are cached in `policy.reputation_cache_dir` as JSON files named by SHA-256 hash, with a configurable TTL (`reputation_cache_ttl_seconds`, default: 86400 seconds / 24 hours). Cache hits bypass the API call.

In offline mode or when `allow_network: false`, the stage returns `ReputationResult::Unknown` without attempting any network call.

HTTP 404 from VT means the hash is unknown (not necessarily clean); the result is `ReputationResult::Unknown`.

### `src/stages/policy.rs` — Policy Decision Stage

Evaluates the collected `PipelineResults` against the loaded `Policy`:

1. **Mandatory hard-wired checks** (cannot be disabled by any policy):
   - Malware detected → FAILED
   - Reputation malicious → FAILED

2. **Configurable decision matrix** — rules evaluated in order; first match wins. Each rule maps a `RuleCondition` to a `RuleVerdict` (failed / unverified / verified).

3. **Policy-level checks** (not in the decision matrix but derived from policy flags):
   - Signature policy (require_signature, executable_handling)
   - File type denylist
   - Executable handling (allow / block_unsigned / deny_all)
   - Malware scan availability
   - Reputation availability
   - SBOM requirement (Phase II hook)

4. **Fallthrough** — if no rule produces a verdict, the result is VERIFIED.

Every evaluated rule, whether matched or not, is recorded in the `decision_trace` array for full audit visibility.

### `src/stages/bundle.rs` — Offline Bundle Stage

Implements offline bundle creation and verification.

**Create:**
- Copies artifact to output directory.
- Computes SHA-256 and SHA-512; writes adjacent checksum files.
- Copies public key files from `keys_dir` to `trusted_keys/`.
- Signs artifact using `sequoia-openpgp` with the provided secret key.
- Walks the output directory to build the manifest (path + SHA-256 per file).
- Signs the manifest.

**Verify:**
- Canonicalizes the bundle path (prevents path traversal via symlinks).
- Loads trusted keys from `trusted_keys/`.
- Verifies `bundle.manifest.sig` over `bundle.manifest.json` before reading any other content.
- Parses the manifest and verifies every listed file's SHA-256.
- Returns the artifact path within the verified bundle.

Path traversal prevention: `safe_bundle_path()` rejects any relative path containing `..` or beginning with `/`.

### `src/stages/mod.rs` — Stages Module Root

Declares and re-exports all stage modules.

### `src/report.rs` — Report Generation

Builds `JsonReport` from pipeline results and renders it to Markdown. Both formats are generated from the same `JsonReport` struct to prevent divergence. The JSON report is written atomically using `util::fs::write_bytes_atomic()`.

### `src/util/command.rs` — Subprocess Utilities

`run_safe()` executes an external binary with:
- Absolute path requirement (rejects relative paths).
- Complete environment clearing (`env_clear()`).
- stdout and stderr captured and bounded.
- `tokio::time::timeout()` wrapping the `wait_with_output()` call.

`tool_version()` runs the binary with `--version` to capture a version string for evidence records.

### `src/util/fs.rs` — Filesystem Utilities

`sha256_file()` computes SHA-256 of a file. `file_size()` returns file size in bytes. `filename_str()` extracts the filename component. `write_bytes_atomic()` writes to a temporary file then renames atomically to prevent partial writes.

### `src/util/net.rs` — Network Utilities

`build_client()` constructs a `reqwest::Client` with a configured timeout and a `User-Agent` identifying the tool. `check_url_allowed()` validates a URL against the policy denylist, returning `VeriError::UrlDenied` on match.

### `src/util/time.rs` — Timestamp Utilities

`iso8601_now()` returns the current UTC time in ISO 8601 format. `elapsed_secs()` computes elapsed seconds from a start instant. `parse_iso8601()` parses an ISO 8601 string for cache TTL checking.

### `src/util/mod.rs` — Utilities Module Root

Declares the `command`, `fs`, `net`, and `time` submodules.

---

## Pipeline Stage Order Invariants

The following invariants are enforced by the orchestrator and must hold for every pipeline run:

1. **Acquire precedes all other stages.** The artifact path is not available until Acquire completes successfully.
2. **Hash follows Acquire immediately.** The artifact hash is computed before any other stage reads the artifact.
3. **Signature, Malware, and Inspect each verify no mutation has occurred** by re-computing SHA-256 and comparing to the value recorded at Acquire. Any deviation terminates the pipeline with FAILED.
4. **Reputation uses the hash computed by the Hash stage**, never a hash computed locally within the Reputation stage.
5. **Policy is always the final stage.** It receives the accumulated `PipelineResults` from all prior stages. It cannot receive partial results.
6. **No stage result can bypass the Policy stage.** Definitive failures (e.g., `MalwareResult::Detected`) are recorded in `PipelineResults` and evaluated by the Policy stage, not short-circuited before it.

Exception: Hash mismatch causes an early FAILED report without completing the remaining stages, because a hash mismatch means the artifact being scanned is not the expected artifact. Continuing subsequent stages on a known-wrong artifact would produce misleading evidence.

---

## Data Flow Diagram

```
 CLI Arguments
      │
      ▼
 ┌─────────────┐
 │  main.rs    │  Parse args, load policy, build RunConfig
 └──────┬──────┘
        │  RunConfig
        ▼
 ┌──────────────────┐
 │   orchestrator   │  Enforces stage order; collects evidence; assembles report
 └──────┬───────────┘
        │
        │ ┌─────────────────────────────────────────────────────┐
        │ │ PIPELINE (mandatory order, cannot be reordered)      │
        │ │                                                       │
        ├─►  Stage 1: acquire    ──► AcquireResult               │
        │ │   (path/URL → local file, SHA-256 at acquire)        │
        │ │                                                       │
        ├─►  assert_no_mutation()                                 │
        │ │                                                       │
        ├─►  Stage 2: hash       ──► HashResult                  │
        │ │   (SHA-256, SHA-512, checksum verification)          │
        │ │                                                       │
        ├─►  assert_no_mutation()                                 │
        │ │                                                       │
        ├─►  Stage 3: signature  ──► SignatureStageResult        │
        │ │   (PGP detached sig, signer fingerprint pinning)     │
        │ │                                                       │
        ├─►  assert_no_mutation()                                 │
        │ │                                                       │
        ├─►  Stage 4: malware    ──► MalwareStageResult         │
        │ │   (ClamAV subprocess, bounded output, clear env)     │
        │ │                                                       │
        ├─►  assert_no_mutation()                                 │
        │ │                                                       │
        ├─►  Stage 5: inspect    ──► InspectStageResult         │
        │ │   (file type, entropy, strings, indicators)          │
        │ │                                                       │
        ├─►  assert_no_mutation()                                 │
        │ │                                                       │
        ├─►  Stage 6: reputation ──► ReputationStageResult      │
        │ │   (VT hash-only lookup, local cache)                 │
        │ │                                                       │
        ├─►  Stage 7: policy     ──► PolicyResult                │
        │ │   (decision matrix eval → VerificationStatus)        │
        │ │                                                       │
        │ └─────────────────────────────────────────────────────┘
        │
        │ All EvidenceItems collected across all stages
        ▼
 ┌───────────────┐
 │  JsonReport   │  Single source of truth for both output formats
 └───────┬───────┘
         │
         ├──► JSON file (--report-json)
         ├──► Markdown file (--report-md)
         └──► stdout (--print-report)

 Exit code derived from JsonReport.verdict.exit_code
```

---

## Trust Boundaries

### Boundary 1: Operator ↔ Veriscan

The operator provides: artifact path or URL, policy file, expected checksums, trusted key directory, signature file. These are validated but treated as external inputs. The policy file is parsed and validated (schema + semantic checks) before use.

**Trust level:** The operator is trusted to provide correct inputs but is not trusted to bypass pipeline stages.

### Boundary 2: Veriscan ↔ Artifact Under Test

The artifact is **untrusted by default**. Its content is read for hashing, signature verification, malware scanning, and static inspection. It is never executed. Path traversal in artifact filenames is not a concern because the artifact path is provided by the operator, not derived from artifact content.

**Trust level:** Zero. The artifact is assumed potentially hostile.

### Boundary 3: Veriscan ↔ ClamAV (subprocess)

ClamAV is invoked via an absolute path specified in the policy. The subprocess environment is completely cleared. stdout and stderr are bounded. The ClamAV binary itself is trusted to be correctly installed by the deploying organization.

**Trust level:** ClamAV binary is trusted; its output is parsed deterministically and bounded.

### Boundary 4: Veriscan ↔ VirusTotal API

Only the SHA-256 hash is sent. The API key is read from an environment variable and used in an HTTP header; it is not logged. The VirusTotal response is parsed as JSON; fields are extracted by key name. The API is a reputation source, not a policy authority; Veriscan makes the final verdict.

**Trust level:** VirusTotal response is trusted as a data source; the policy engine makes the verdicts.

### Boundary 5: Veriscan ↔ Offline Bundle

The bundle directory is treated as untrusted until the manifest signature is verified. No file in the bundle is read for content until `bundle.manifest.sig` passes verification. Path components in the manifest are validated against traversal patterns.

**Trust level:** Bundle content is untrusted until manifest signature passes; trusted thereafter to the extent of the signing key.

### Boundary 6: Veriscan ↔ Report Consumers (SIEM, Auditors)

JSON reports are written atomically. Evidence `deterministic_id` fields allow consumers to verify that individual evidence records have not been tampered with after generation. The policy digest in every report allows consumers to verify the exact policy in effect.

**Trust level:** Report consumers can independently verify evidence record integrity using the `deterministic_id` mechanism.

---

## Artifact Hash Tracking

The artifact SHA-256 is tracked at the following checkpoints:

| Checkpoint | Location | Purpose |
|---|---|---|
| At acquire | `AcquireResult.sha256_at_acquire` | Baseline hash immediately after file is placed on disk |
| After hash stage | `orchestrator::assert_no_mutation()` | Verify no mutation during hash computation |
| After signature stage | `orchestrator::assert_no_mutation()` | Verify no mutation during sig verification |
| After malware stage | `orchestrator::assert_no_mutation()` | Verify no mutation during ClamAV scan |
| After inspect stage | `orchestrator::assert_no_mutation()` | Verify no mutation during static analysis |
| In JsonReport | `report.hashes.sha256` | Permanent record in the output report |
| In evidence | Hash stage `EvidenceItem.outputs.sha256` | Auditable record in evidence chain |

If any mutation check fails, `VeriError::ArtifactMutated` is returned with both the `before` and `after` hash values.

---

## Policy Enforcement Model

Policy enforcement operates on two levels:

### Level 1: Mandatory Invariants (Non-Configurable)

These checks are hardcoded in `stages/policy.rs::evaluate()` and cannot be disabled by any policy configuration:
- Malware detected → FAILED (always)
- Reputation malicious → FAILED (always)

These represent absolute security boundaries. No policy operator can override them.

### Level 2: Configurable Policy Matrix

Policy operators declare rules in the `decision_matrix` array. Rules are evaluated in declaration order; first match wins. Each rule maps a `RuleCondition` to a `RuleVerdict`. Conditions include: `malware_detected`, `signature_missing`, `signature_invalid`, `signer_not_allowed`, `checksum_mismatch`, `high_entropy`, `denied_file_type`, `reputation_malicious`, `reputation_unavailable`, `malware_scan_unavailable`, `sbom_missing`, `always`.

Beyond the decision matrix, policy-level checks derived from boolean flags (`require_signature`, `require_checksums`, `malware_scan_required`, `reputation_required`, `require_sbom`) are evaluated after the matrix.

### Level 3: Policy Digest Binding

The SHA-256 digest of the serialized policy is recorded in every JSON report. This binds the verdict to the exact policy configuration, enabling auditors to detect policy tampering between runs.

---

## Evidence Chain of Custody

Each pipeline stage produces one or more `EvidenceItem` records assembled into `all_evidence` by the orchestrator. The final `JsonReport.evidence` array contains all evidence in pipeline stage order.

An `EvidenceItem` contains:
- `timestamp` — ISO 8601 UTC when evidence was collected.
- `stage_name` — canonical name of the stage.
- `inputs` — named string inputs (artifact path, expected hash, sig path, key path, API source).
- `outputs` — named typed JSON values (computed hashes, verification status, detection results, entropy, indicators).
- `tool_versions` — version strings of external tools invoked (ClamAV version, etc.).
- `deterministic_id` — SHA-256 of the canonical form: `stage:<name>|timestamp:<ts>|in:<k>=<v>|...|out:<k>=<json_v>|...` with keys sorted alphabetically.

The `deterministic_id` allows any consumer of the JSON report to independently verify that the evidence record has not been modified after generation by re-computing the hash from the record's contents.

---

## Supported Platforms

| Platform | Architecture | Status |
|---|---|---|
| Linux | x86-64 | Primary; fully tested |
| Linux | aarch64 | Supported; pure-Rust backend is architecture-agnostic |
| macOS | x86-64 | Supported; ClamAV via Homebrew |
| macOS | arm64 (Apple Silicon) | Supported |
| Windows | x86-64 | Native Windows builds are not tested; use WSL 2 or Docker with a Linux container |
