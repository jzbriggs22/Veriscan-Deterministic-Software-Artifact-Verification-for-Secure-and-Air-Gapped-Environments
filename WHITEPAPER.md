# veriscan Technical Whitepaper

## Deterministic Software Artifact Verification for Secure and Air-Gapped Environments

**Version:** 1.0
**Date:** 2026-02-25
**Classification:** Unclassified / Public

---

## Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [Problem Statement](#2-problem-statement)
3. [Design Goals and Non-Goals](#3-design-goals-and-non-goals)
4. [Threat Model and Trust Boundaries](#4-threat-model-and-trust-boundaries)
5. [Pipeline Architecture](#5-pipeline-architecture)
6. [Evidence Model and Auditability](#6-evidence-model-and-auditability)
7. [Offline Verification Bundles](#7-offline-verification-bundles)
8. [Policy Engine Rationale](#8-policy-engine-rationale)
9. [Mapping to NIST 800-53 Rev 5 and NIST 800-161](#9-mapping-to-nist-800-53-rev-5-and-nist-800-161)
10. [Limitations and Assumptions](#10-limitations-and-assumptions)
11. [Operational Guidance](#11-operational-guidance)
12. [Future Work](#12-future-work)
13. [Appendix A: Example JSON Report Structure](#appendix-a-example-json-report-structure)
14. [Appendix B: Example Policy YAML Snippet](#appendix-b-example-policy-yaml-snippet)
15. [Appendix C: Example Evidence Item](#appendix-c-example-evidence-item)

---

## 1. Executive Overview

Software artifacts—compiled binaries, container images, release archives—travel through an increasingly complex supply chain before reaching production systems. Each handoff point represents an opportunity for adversarial insertion:

- **Upstream mirror compromise**: Modified artifacts served from legitimate-looking CDN mirrors
- **MITM during download**: TLS downgrade or certificate forgery in network-isolated environments
- **Insider modification**: Build engineers or package maintainers with signing key access
- **CI/CD pipeline injection**: Malicious stages inserted into build pipelines
- **Bundle tampering**: Offline delivery packages with silently modified contents

Existing verification workflows are typically ad hoc: a developer might verify a GPG signature, or check a SHA-256 checksum, but rarely both, rarely systematically, and almost never with machine-readable audit evidence.

`veriscan` provides a single, auditable entry point for artifact verification that enforces a mandatory multi-stage pipeline, captures structured evidence, and produces typed verdicts consumable by automated systems.

---

## 2. Design Principles

### 2.1 Mandatory Pipeline

Every invocation of `veriscan` runs all applicable pipeline stages in a fixed order:

```
Acquire → Hash → Signature → Malware → Inspect → Reputation → Policy
```

No stage can be skipped via CLI flags, environment variables, or policy configuration. Policy controls _how_ each stage is evaluated (e.g., whether a missing signature is fatal), not _whether_ the stage runs.

### 2.2 Fail-Closed

When information is absent or ambiguous, `veriscan` fails toward the more conservative verdict. A missing signature is UNVERIFIED (or FAILED under strict policy), never VERIFIED. A tool that cannot be found is reported, not silently skipped.

### 2.3 Typed Verdicts

`veriscan` uses a three-state verdict model:

| Status | Exit Code | Meaning |
|--------|-----------|---------|
| VERIFIED | 0 | All required checks passed |
| UNVERIFIED | 10 | One or more checks incomplete (tool missing, optional check) |
| FAILED | 20 | Definitive failure (hash mismatch, malware, invalid sig) |
| Tool Error | 99 | Configuration error, I/O failure |

Boolean pass/fail is insufficient for automated pipelines. UNVERIFIED enables policy-specific handling: a CI gate might warn on UNVERIFIED but block on FAILED.

### 2.4 Structured Evidence

Every pipeline stage produces a structured `EvidenceItem` with:
- Stage name and timestamp
- Named inputs and typed outputs
- Tool version information
- A deterministic SHA-256 ID computed from the canonical evidence representation

Evidence items form an append-only audit chain. No stage can retroactively modify evidence from a prior stage.

### 2.5 No Artifact Execution

`veriscan` never executes the artifact being verified. All analysis is read-only: hash computation, signature verification over bytes, static string extraction, and subprocess invocation of external scanners with the artifact path as argument only.

### 2.6 Mutation Detection

After each pipeline stage, `veriscan` recomputes the artifact's SHA-256 and compares it to the hash established at acquire time. Any in-pipeline mutation produces an immediate hard failure with `ArtifactMutated` error code.

---

## 3. Pipeline Architecture

### 3.1 Acquire Stage

The acquire stage establishes the artifact on local disk:

- **Local path**: File is read from the specified path; size and initial SHA-256 are recorded.
- **URL (https://)**: The URL is validated against `policy.url_patterns_denylist` before any network activity. The artifact is downloaded using a non-redirecting TLS client and written to a temporary file with atomic rename semantics.
- **Offline mode**: No network activity is permitted; artifact must already be present locally.

The SHA-256 computed at acquire (`sha256_at_acquire`) becomes the mutation baseline for all subsequent stages.

### 3.2 Hash Stage

Computes SHA-256 and SHA-512 of the artifact in a single streaming pass (64 KiB buffer, no full-file copy). If expected checksums are provided via CLI or adjacent checksum files (`<artifact>.sha256`, `<artifact>.sha512`), they are compared against the computed digests. A mismatch produces an immediate `HashMismatch` hard error.

Priority for expected checksums:
1. Explicit CLI argument (`--expected-sha256`, `--expected-sha512`)
2. Adjacent checksum file (`<artifact>.sha256` / `<artifact>.sha512`)
3. If `policy.require_checksums = true` and no source found → hard error

### 3.3 Signature Stage

PGP detached signature verification using `sequoia-openpgp` (pure-Rust, `crypto-openssl` backend):

1. Locate the signature file: explicit `--sig` path, or `<artifact>.asc` / `<artifact>.sig`
2. Load trusted public keys from `--trusted-keys` directory or policy `allow_signers`
3. Build a `DetachedVerifier` with a `StandardPolicy`
4. Run verification; on success, extract signer UID and fingerprint
5. If `policy.allow_signers` is non-empty, check the verified fingerprint against the allowlist

Possible outcomes: `Verified`, `Missing`, `Invalid`, `SignerNotAllowed`, `ToolMissing`

### 3.4 Malware Stage

ClamAV integration via safe subprocess:
- Binary path must be absolute (from `policy.malware_tool_path` or standard paths)
- `env_clear()` applied before invocation (no secret leakage)
- No shell invocation; arguments passed directly as `&[OsStr]`
- Bounded output capture (default 1 MiB)
- Timeout enforced via `tokio::time::timeout`
- Exit code interpretation: 0=clean, 1=detections found, 2=scan error

When `clamscan` is not found: `MalwareResult::ToolMissing`. Whether this is fatal is controlled by `policy.malware_failure_is_fatal`.

### 3.5 Inspect Stage

Static file analysis without execution:

- **File type detection**: Magic-byte matching for ELF, PE, Mach-O, ZIP, GZIP, BZIP2, XZ, PDF, PNG, JPEG, scripts; extension fallback for `.exe`, `.dll`, `.ps1`
- **Shannon entropy**: Computed over a bounded sample (default 1 MiB) using 8-bit symbol distribution. Entropy near 8.0 indicates encrypted or packed content.
- **String extraction**: Printable ASCII sequences ≥ min_length, bounded to avoid unbounded memory use
- **Indicator scanning**: URL patterns (`https?://[^\s"'<>]{8,}`), PowerShell execution patterns (`Invoke-Expression`, `DownloadString`, `EncodedCommand`), base64 blobs (`[A-Za-z0-9+/]{64,}={0,2}`)

No classification is made ("this is malware"). Indicators are reported as observable measurements for the policy stage and human review.

### 3.6 Reputation Stage

VirusTotal v3 API hash-only lookup:
- Only the SHA-256 hash is submitted — **the artifact bytes are never uploaded**
- API key read exclusively from environment variable (name configured in policy)
- API key is never logged, never written to disk, never included in evidence
- Results cached locally (configurable TTL, default 24 hours) to minimize API traffic
- Offline mode (`policy.allow_network = false`): stage returns `Unavailable` without error
- 404 response (hash not found): `Unknown` status — not a failure

Possible outcomes: `Clean`, `Malicious`, `Unknown`, `Unavailable`

### 3.7 Policy Stage

The decision engine applies the `decision_matrix` rules in declaration order (first match wins). Each rule maps a `RuleCondition` to a `RuleVerdict`. Every rule evaluation is recorded in the `decision_trace`.

Built-in hard rules (always applied before the decision matrix):
1. **MalwareDetected → FAILED** (unconditional, no policy escape)
2. **ReputationMalicious → FAILED** (unconditional, no policy escape)

Policy-level checks applied after the matrix:
- `require_signature`: missing or invalid sig → FAILED
- `deny_file_types`: matching file type → FAILED
- `executable_handling`: `BlockUnsigned` or `DenyAll` for executables
- `malware_scan_required` + `malware_failure_is_fatal`: missing tool → FAILED or UNVERIFIED
- `reputation_required` + `reputation_failure_is_fatal`: unavailable → FAILED or UNVERIFIED

The final verdict is the most severe status encountered.

---

## 4. Evidence Model

### 4.1 EvidenceItem

```json
{
  "timestamp": "2024-01-15T10:23:45.123Z",
  "stage_name": "hash",
  "inputs": {
    "artifact_path": "/path/to/artifact.tar.gz",
    "expected_sha256": "abc123..."
  },
  "outputs": {
    "sha256": "abc123...",
    "sha512": "def456...",
    "sha256_matched": true
  },
  "tool_versions": {},
  "deterministic_id": "3a7f9b2c..."
}
```

### 4.2 Deterministic IDs

The `deterministic_id` is the SHA-256 of the canonical JSON representation of `(stage_name, inputs, outputs)`. This enables:
- Independent verification of evidence without rerunning the tool
- Detection of evidence tampering in stored reports
- Cross-correlation of evidence across audit systems

### 4.3 Decision Trace

```json
[
  {
    "rule_description": "Malware detected — hard block",
    "condition": "MalwareDetected",
    "matched": false,
    "verdict": null
  },
  {
    "rule_description": "SHA-256 verified",
    "condition": "HashVerified",
    "matched": true,
    "verdict": "Verified"
  }
]
```

The trace is ordered and complete: every evaluated rule appears, including non-matched rules. This enables auditors to understand both what fired and what was considered.

---

## 5. Offline Bundle Format

For air-gapped environments, `veriscan` supports a self-contained verification bundle:

```
bundle/
  artifact.tar.gz            # The artifact
  artifact.tar.gz.sha256     # SHA-256 checksum (hex)
  artifact.tar.gz.sha512     # SHA-512 checksum (hex)
  artifact.tar.gz.sig        # PGP detached signature
  trusted_keys/
    signing_pub.asc           # Trusted public keys
  bundle.manifest.json        # File registry with SHA-256
  bundle.manifest.sig         # PGP signature over manifest
```

**Verification order (fail-closed):**
1. Verify `bundle.manifest.sig` over `bundle.manifest.json` using trusted keys (failure → immediate abort)
2. Verify SHA-256 of every file listed in the manifest (failure → immediate abort)
3. Verify artifact signature using trusted keys
4. Run the full pipeline on the verified artifact

Path traversal is prevented: no bundle file path may start with `/` or contain `..`.

---

## 6. Policy Configuration

Policies are YAML files with a stable, validated schema. Four built-in policies are provided:

| Policy | Target Environment |
|--------|-------------------|
| `default.yaml` | General verification |
| `contractor_strict.yaml` | High-assurance defense environments |
| `airgapped.yaml` | Air-gapped / no-network |
| `ci_gate.yaml` | Automated CI/CD pipeline gating |

Key policy fields:

```yaml
name: "contractor_strict"
version: "1.0"
require_signature: true
allow_unsigned: false
allow_network: true
require_checksums: true
malware_scan_required: true
malware_failure_is_fatal: true
reputation_required: true
reputation_failure_is_fatal: false
deny_file_types: []
allow_signers: []
max_entropy_threshold: 7.8
executable_handling: BlockUnsigned
decision_matrix:
  - description: "Hash verified"
    condition: {type: "hash_verified"}
    verdict: Verified
  - description: "Signature verified"
    condition: {type: "signature_verified"}
    verdict: Verified
```

Policy integrity is verified via `policy.digest()` — the SHA-256 of the serialized policy. This digest is included in every JSON report, enabling cryptographic binding of verdicts to the exact policy version used.

---

## 7. Security Properties

### 7.1 No Artifact Execution

`veriscan` is designed so that the artifact under verification is never executed at any point during the pipeline. The malware stage invokes `clamscan` as a separate process with the artifact path as an argument; `clamscan` may read the artifact, but `veriscan` itself only reads artifact bytes for hashing and static inspection.

### 7.2 Subprocess Isolation

External tools (ClamAV) are invoked with:
- Absolute path required (no PATH lookup, no shell)
- `env_clear()`: no environment variable inheritance
- `kill_on_drop(true)`: subprocess killed if `veriscan` panics
- `tokio::time::timeout`: bounded execution time
- Bounded stdout/stderr capture: no unbounded memory growth

### 7.3 API Key Security

The VirusTotal API key is read from an environment variable at runtime. It is:
- Never stored in policy files
- Never included in JSON or Markdown reports
- Never logged (not even at debug level)
- Never written to the reputation cache

### 7.4 Path Safety

All file paths from external sources (bundle manifests, checksum files) are validated to prevent path traversal. Bundle file paths are rejected if they are absolute or contain `..` components.

### 7.5 Deterministic Behavior

Given identical inputs (artifact, policy, expected checksums, trusted keys), `veriscan` produces byte-for-byte identical JSON reports (except for UUID run_id and timestamps). This property enables independent verification of reported evidence.

---

## 8. Compliance and Standards Alignment

`veriscan` implements controls relevant to:

- **NIST SP 800-53 Rev 5**: SA-12 (Supply Chain Risk Management), SI-7 (Software, Firmware, and Information Integrity), AU-2, AU-9, AU-10 (Audit and Accountability)
- **NIST SP 800-161 Rev 1**: SCRM practices for software integrity verification at ingestion
- **CISA SBOM Guidance**: Evidence model supports SBOM integration
- **EO 14028**: Software supply chain security requirements for federal systems
- **DoD STIG**: Artifact verification controls in secure software delivery

See [docs/controls/nist_800_53_rev5.md](docs/controls/nist_800_53_rev5.md) and [docs/controls/nist_800_161.md](docs/controls/nist_800_161.md) for detailed control mappings.

---

## 9. Implementation Notes

### Language and Dependencies

`veriscan` is implemented in Rust (MSRV 1.70+). Key design decisions:

- **Pure-Rust crypto**: `sequoia-openpgp` with `crypto-openssl` backend provides PGP verification without binding to system `libgpg`. This simplifies deployment in minimal container images.
- **Async runtime**: `tokio` enables concurrent I/O (HTTP downloads, subprocess monitoring) without blocking the main thread.
- **No unsafe code**: The codebase contains no `unsafe` blocks (excluding macro-generated code from dependencies).
- **No C library dependencies for core functions**: Hash computation (`sha2`), serialization (`serde`), and logging (`tracing`) are pure-Rust.

### Test Coverage

The test suite includes:
- **Unit tests**: Policy engine, evidence model, hash stage, inspect stage
- **Integration tests**: Pipeline invariants (55 tests across 4 test suites)
- **Doc tests**: API examples verified at compile time

### Build Reproducibility

The release build uses `lto = true`, `codegen-units = 1`, and `strip = true`. With a pinned toolchain (`rust-toolchain.toml`), builds are deterministic on the same platform.

---

## 10. Limitations and Non-Goals

`veriscan` deliberately does not:

- **Execute artifacts**: Dynamic analysis is out of scope; use sandboxed execution environments
- **Detect zero-days**: Malware detection relies on ClamAV signatures; novel malware is not detected
- **Verify build reproducibility**: Reproducible build workflows require separate tooling
- **Audit the signing key lifecycle**: Key management, rotation, and revocation are out of scope
- **Replace SBOM workflows**: `veriscan` complements, not replaces, SBOM generation and analysis tools

---

## 11. Conclusion

`veriscan` provides a rigorous, auditable, and deployable solution to the software artifact verification problem. Its mandatory pipeline, typed verdicts, structured evidence, and offline bundle support make it suitable for use in the most demanding regulated environments—from DoD contractor delivery workflows to air-gapped CI/CD systems.

By treating every pipeline decision as a structured, traceable, machine-readable record, `veriscan` enables organizations to move from ad hoc verification to systematic, evidence-based artifact intake.

---

*For integration guidance, see [docs/demo_guide.md](docs/demo_guide.md). For the full threat model, see [docs/threat_model.md](docs/threat_model.md).*
