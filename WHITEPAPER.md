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

Software supply chain attacks have become one of the most consequential threat vectors in enterprise and defense computing environments. The compromise of software distribution infrastructure — from build servers to package mirrors to vendor delivery mechanisms — enables adversaries to insert malicious code into the update pipelines of thousands of organizations simultaneously. The 2020 SolarWinds incident, the 2021 Kaseya VSA attack, and the 2024 XZ Utils backdoor each demonstrated that trusted delivery channels can be weaponized at scale, and that conventional endpoint security controls are often insufficient to detect supply chain intrusions before damage occurs.

**veriscan** is a purpose-built, defense-grade command-line tool for software artifact verification. It enforces a mandatory, ordered, seven-stage verification pipeline over any software artifact before that artifact is allowed to proceed to staging, deployment, or installation. The pipeline combines cryptographic integrity verification, PGP signature authentication, ClamAV-based malware scanning, static content inspection, and threat intelligence correlation into a single, auditable workflow. Every decision produced by the pipeline is backed by structured, machine-readable evidence with deterministic identifiers that support chain-of-custody documentation.

veriscan is designed to operate in environments that range from fully connected enterprise networks to completely air-gapped classified enclaves. Its offline bundle feature allows artifacts and all their verification metadata to be cryptographically sealed, transferred across an air gap, and re-verified in a network-isolated environment without any reduction in assurance.

Key design properties:

- **No artifact execution:** The tool never executes, loads, or interprets the artifact under examination.
- **Fail-closed:** Unexpected conditions produce restrictive outcomes; there is no silent pass.
- **Typed verdicts:** Trust is not represented as a boolean; it is represented as one of three typed, non-interchangeable outcomes.
- **Policy-driven and auditable:** Every behavior is configured in a versioned, hash-digested YAML policy document.
- **Pure-Rust cryptography:** No dependency on system OpenSSL or GnuPG for cryptographic operations.
- **Air-gap native:** Offline bundles provide complete verification capability without network access.

This whitepaper describes the design rationale, architecture, evidence model, threat model, and operational deployment guidance for veriscan. It also maps veriscan's controls to relevant NIST frameworks and honestly describes the tool's limitations.

---

## 2. Problem Statement

### 2.1 The Software Supply Chain Attack Surface

Modern software deployments depend on a long and complex supply chain: upstream open-source repositories, commercial vendor packages, build automation systems, artifact registries, content delivery networks, and package mirrors. Each link in this chain represents an opportunity for an adversary to introduce malicious content that will be distributed to downstream consumers as trusted software.

The adversarial capability required to execute a supply chain attack has decreased dramatically. Nation-state actors, organized criminal groups, and even well-resourced individual threat actors can:

- Compromise build infrastructure to inject malicious code at compile time.
- Hijack package signing keys or create typosquatted packages that shadow legitimate ones.
- Intercept artifact downloads via man-in-the-middle attacks on distribution mirrors.
- Tamper with package registries or CDN edge nodes to serve modified artifacts.
- Purchase or socially engineer their way into the trust chains of open-source projects.

### 2.2 Mirror Tampering and Download Integrity

Even when a vendor's signing infrastructure is intact, the path from vendor to end consumer passes through a distribution network that is not fully under the consumer's control. Package mirrors are operated by third parties, CDN nodes are shared infrastructure, and network paths to download servers can be influenced by adversaries with BGP hijacking capabilities.

A consumer who downloads `vendor-package-3.2.1.tar.gz` has no inherent assurance that the bytes received match the bytes the vendor intended to distribute. Without cryptographic verification against a trusted expected value:

- A CDN edge node serving a compromised copy would be indistinguishable from the legitimate mirror.
- A network-path adversary performing a downgrade or substitution attack would succeed silently.
- A storage corruption event on the mirror host could go undetected.

### 2.3 The Air-Gapped Environment Challenge

Air-gapped environments — networks physically or logically isolated from the internet — present a particular verification challenge. Artifacts must be transferred across the air gap by physical media. Without a verification workflow:

- There is no assurance that the artifact on the transfer media matches the artifact that was approved in the connected environment.
- The transfer process itself is an opportunity for substitution.
- There is no record of which verification checks were performed on the artifact before it was admitted.

Existing tools often require network access for threat intelligence lookups or do not produce structured evidence records suitable for air-gapped operations.

### 2.4 The Absence of Structured, Auditable Verification Records

Even in organizations that perform artifact verification, the verification process is often manual and inconsistent, undocumented, and unverifiable by auditors. Audit findings related to supply chain controls frequently cite the absence of documented, verifiable evidence that software artifacts were inspected before deployment. A verification tool that does not produce structured, auditable evidence of its decisions provides limited compliance value.

---

## 3. Design Goals and Non-Goals

### 3.1 Design Goals

**G1 — Deterministic, reproducible verification**
Given the same artifact, the same policy, and the same expected checksums and signing keys, veriscan must produce the same verdict on every run. Verification is not probabilistic or heuristic.

**G2 — Structured, auditable evidence**
Every verification run must produce machine-readable evidence that a human or automated system can use to reconstruct exactly what was checked, what was found, and why the verdict was reached.

**G3 — Air-gap compatibility**
The full verification workflow must be executable in a network-isolated environment. Network-dependent checks must degrade gracefully and be visible in the output rather than silently passing.

**G4 — Fail-closed defaults**
The default behavior when something is uncertain or unavailable must be a restrictive outcome. Operators can relax individual constraints in the policy; they cannot silently bypass the framework.

**G5 — No artifact execution**
The tool must not execute, dynamically load, or invoke the artifact under any circumstances during the verification process.

**G6 — Policy as code**
Verification behavior must be fully specified in a versioned, human-readable, and machine-parseable policy document. No hidden defaults. No configuration options that bypass the framework.

**G7 — CI/CD integration**
Verification outcomes must be expressed as standard process exit codes consumable by CI/CD pipelines without additional parsing.

**G8 — Defense contractor grade**
The tool must be suitable for use in environments subject to DFARS 252.204-7012, NIST SP 800-171, and related cybersecurity requirements for defense contractors.

### 3.2 Non-Goals

**NG1 — Dynamic behavioral analysis**
veriscan does not sandbox-execute artifacts to observe runtime behavior. Static analysis is supplementary, not the primary verification mechanism.

**NG2 — Complete malware detection**
veriscan is not a replacement for endpoint detection and response (EDR) or a complete anti-malware platform. The ClamAV integration and static inspection are one layer of defense.

**NG3 — Build system verification**
veriscan verifies artifacts produced by a build system but does not verify the build system itself. Reproducible build workflows are complementary tooling.

**NG4 — Key management**
veriscan enforces signature policies and signer fingerprint pinning but does not manage cryptographic keys, implement key ceremonies, or handle key revocation. Key management is an organizational function.

**NG5 — Regulatory certification**
veriscan does not seek or claim any compliance certification. It is a tool that supports compliance programs.

---

## 4. Threat Model and Trust Boundaries

### 4.1 Attacker Profiles

veriscan's design addresses the following attacker profiles:

| Attacker | Capability | In Scope? |
|----------|-----------|-----------|
| Supply chain adversary | Modify artifacts on distribution mirrors or CDN | Yes |
| MITM / network attacker | Intercept and replace artifact during download | Yes |
| Malware author | Distribute malware as a legitimate-looking artifact | Yes (signature-based) |
| Insider (limited access) | Introduce unsigned or improperly-signed artifacts | Yes |
| Mirror operator | Serve modified artifact bytes | Yes |
| Nation-state (signed release) | Compromise upstream vendor signing key | Partially (key pinning limits impact) |
| Insider (key access) | Sign malicious artifacts with legitimate keys | No — requires key management controls |
| Compiler / toolchain adversary | Inject malicious code at build time | No — requires reproducible builds |
| Zero-day malware author | Novel malware with no signatures | No — signature-based detection only |

### 4.2 Trust Boundaries

```
+------------------------------------------------------------------+
|                       UNTRUSTED ZONE                            |
|                                                                  |
|  [Artifact Source]  [Mirror / CDN]  [VirusTotal API]            |
|  (URL or path)      (download path) (hash only, no upload)      |
+--------+-----------------+-------------------+------------------+
         |                 |                   |
         v                 v                   v
+------------------------------------------------------------------+
|                  VERIFICATION BOUNDARY                          |
|                                                                  |
|  veriscan CLI                                                    |
|  Pipeline: Acquire -> Hash -> Sig -> AV -> Inspect ->           |
|            Reputation -> Policy                                 |
|                                                                  |
|  [Policy file (YAML)]   [Trusted keys directory]                |
+------------------------------------------+-----------------------+
                                           |
                                           v
+------------------------------------------------------------------+
|                    TRUSTED ZONE (output)                        |
|                                                                  |
|  JSON Report + Markdown Report + Audit Logs                     |
|  (consumed by CI/CD gate, SIEM, change management)              |
+------------------------------------------------------------------+
```

### 4.3 What veriscan Defends Against

| Threat | Defense Mechanism |
|--------|------------------|
| Corrupted downloads / bit flips | SHA-256 and SHA-512 verification against expected values |
| Mirror substitution / MITM | Hash verification; PGP signature verification |
| Unsigned artifact injection | `require_signature: true`; `executable_handling: block_unsigned` |
| Wrong signer | `allow_signers` fingerprint pinning |
| Known malware | ClamAV signature scan |
| Known-bad reputation | VirusTotal hash lookup |
| Obfuscated / packed content | Shannon entropy flagging |
| Dangerous file types | `deny_file_types`; file type detection |
| HTTP (plaintext) download sources | `url_patterns_denylist: ["http://"]` |
| In-pipeline artifact mutation | Inter-stage SHA-256 re-verification |
| Bundle tampering in transit | Manifest signature + per-file hash verification |
| Path traversal in bundles | `safe_bundle_path` validation |
| Secret leakage via subprocess | `env_clear()` before external tool invocation |

### 4.4 Trust Assumptions

veriscan operates under the following trust assumptions:

1. The verification environment (the host running veriscan) is trusted and not compromised.
2. The policy file is access-controlled and its contents are managed through a change process.
3. Trusted key material was obtained through an authenticated out-of-band process.
4. ClamAV signature databases are maintained and regularly updated on the verification host.
5. VirusTotal is available and its results are reasonably accurate for the query window.

---

## 5. Pipeline Architecture

### 5.1 Overview

veriscan enforces a mandatory, ordered, seven-stage pipeline. No CLI flag, environment variable, or policy setting can reorder, skip, or remove stages. Policy controls the behavior of individual stages but cannot bypass the pipeline structure.

```
[Acquire] -> [Hash] -> [Signature] -> [Malware] -> [Inspect] -> [Reputation] -> [Policy]
```

After each stage, the orchestrator re-hashes the artifact on disk and compares the result to the hash recorded at acquisition time. Any difference triggers an immediate `FAILED` with `ERR_ARTIFACT_MUTATED`, addressing time-of-check/time-of-use (TOCTOU) concerns.

### 5.2 Stage 1: Acquire

The acquire stage obtains the artifact and establishes its baseline cryptographic identity.

- If the source is a local path: reads the artifact to compute an initial SHA-256.
- If the source is a URL: validates against `url_patterns_denylist` before connecting; downloads via HTTPS; streams to disk atomically.
- Records artifact filename, size in bytes, and initial SHA-256.
- Network access is governed by `allow_network` in the policy.

**Evidence:** Acquisition method, source URL or path, filename, size, initial hash.

### 5.3 Stage 2: Hash

Computes and verifies cryptographic digests.

- Computes SHA-256 and SHA-512 over the complete artifact byte stream in a single streaming pass (64 KiB I/O buffer).
- Compares against expected values from: explicit `--expected-sha256` / `--expected-sha512` CLI arguments; adjacent checksum files (e.g., `artifact.tar.gz.sha256`); or fails if `require_checksums: true` and no expected value is found.
- A hash mismatch is an immediate hard `FAILED` (`ERR_HASH_MISMATCH`) — not a warning.

**Evidence:** Artifact path, expected values, computed values, match status.

### 5.4 Stage 3: Signature

Verifies PGP detached signatures using pure-Rust cryptography (`sequoia-openpgp` with `crypto-rust` feature).

- Locates the signature file via `--sig` argument, or `<artifact>.sig` / `<artifact>.asc`.
- Loads trusted public keys from `--trusted-keys` directory or bundle's `trusted_keys/` subdirectory.
- Performs PGP detached signature verification with `StandardPolicy`.
- If `allow_signers` is non-empty, checks verified fingerprint against the allow list.
- Records signer UID and fingerprint on success.

**Outcomes:** `Verified`, `Missing`, `Invalid`, `SignerNotAllowed`, `NotChecked`

**Evidence:** Signature file path, fingerprint, signer UID, verification status.

### 5.5 Stage 4: Malware

Invokes ClamAV for signature-based malware detection.

- Locates `clamscan` at the configured path or standard system paths (`/usr/bin/clamscan`, etc.).
- Invokes via a hardened subprocess wrapper: cleared environment (`env_clear()`), absolute path required, bounded output (default 64 KiB), hard timeout (default 120 seconds), stdin closed, killed on drop.
- Parses exit code: 0 = clean, 1 = detections, 2 = scan error.
- Records ClamAV version in evidence.

**Outcomes:** `Clean`, `Detected`, `ToolMissing`, `ScanError`

**Evidence:** Tool path, engine version, scan status, detection names (if any).

### 5.6 Stage 5: Inspect

Performs static analysis of artifact content without execution.

- Detects file type using magic bytes (ELF, PE, Mach-O, ZIP, GZIP, BZIP2, XZ, PDF, PNG, JPEG, RPM, DEB, WASM, Java class, scripts) with extension fallback.
- Computes Shannon entropy over a sampled byte range (default 1 MiB). Flags if entropy exceeds `max_entropy_threshold` (default 7.2 bits/byte).
- Extracts printable ASCII strings (minimum `min_string_length` characters, up to `max_inspection_strings` total).
- Scans extracted strings for indicators: URL patterns, PowerShell execution keywords (`Invoke-Expression`, `IEX`, `FromBase64String`, etc.), shell patterns (`curl -o`, `wget -O`, `/dev/tcp/`, `nc -e`, `LD_PRELOAD`), and base64 blobs.
- Classifies artifact as executable, script, or data.

**Evidence:** File type, entropy value, entropy flagged status, indicator list, strings sample.

### 5.7 Stage 6: Reputation

Checks the artifact's hash against external threat intelligence.

- In offline mode or when `allow_network: false`: skips gracefully with `Unknown` status.
- Checks local disk cache for a fresh result (TTL default 24 hours).
- Reads VirusTotal API key from environment variable named in `vt_api_key_env`. The key value is never logged or stored.
- Submits GET to `https://www.virustotal.com/api/v3/files/<sha256>`. Only the hash is transmitted; artifact bytes are never uploaded.
- Parses `last_analysis_stats`: malicious + suspicious = detected engines.
- Caches result to disk for subsequent runs.

**Outcomes:** `Clean`, `Malicious` (always FAILED), `Unknown`, `ApiKeyMissing`, `Unavailable`

**Evidence:** SHA-256 submitted, source, engines total/detected, reputation label.

### 5.8 Stage 7: Policy

Evaluates collected pipeline results against the decision matrix and policy rules to produce the final typed verdict.

- Applies two mandatory hardwired checks first (cannot be overridden):
  1. `MalwareResult::Detected` → always `FAILED`.
  2. `ReputationResult::Malicious` → always `FAILED`.
- Evaluates `decision_matrix` rules in declaration order; first match wins.
- Applies policy-level checks: signature requirement, file type denylist, executable handling, malware scanner availability, reputation availability, SBOM requirement.
- Records every rule evaluation (matched or not) in the `decision_trace`.
- Computes the policy digest and includes it in the evidence.
- Falls through to `VERIFIED` if no rule triggers a worse outcome.

**Evidence:** Policy name, version, digest, rules evaluated count, full decision trace.

---

## 6. Evidence Model and Auditability

### 6.1 Evidence Item Structure

Every pipeline stage produces one or more `EvidenceItem` records:

```rust
pub struct EvidenceItem {
    pub timestamp: String,         // ISO 8601 UTC
    pub stage_name: String,        // "acquire" | "hash" | "signature" | ...
    pub inputs: HashMap<String, String>,
    pub outputs: HashMap<String, Value>,    // typed JSON values
    pub tool_versions: HashMap<String, String>,
    pub deterministic_id: String,  // SHA-256 of canonical serialization
}
```

The `deterministic_id` is computed as the SHA-256 of a canonicalized string that sorts all keys lexicographically before hashing. This ensures:
1. The same evidence content always produces the same `deterministic_id`, regardless of HashMap insertion order.
2. Any post-hoc modification of an evidence record will produce a different `deterministic_id`, making tampering detectable.

### 6.2 Chain of Custody

The evidence chain for a successful verification run contains the following items:

| Stage | Key Evidence |
|-------|-------------|
| `acquire` | Source, filename, size, initial SHA-256 |
| `hash` | Expected/actual SHA-256 and SHA-512, match status |
| `signature` | Signature file path, fingerprint, signer UID, status |
| `malware` | Tool path, ClamAV version, scan status, detections |
| `inspect` | File type, entropy, indicators, strings sample |
| `reputation` | SHA-256 submitted, source, engines total/detected |
| `policy` | Policy name/version/digest, rules evaluated, full decision trace |

Each item's `deterministic_id` can be independently recomputed from the item's content, allowing an auditor to verify that evidence records have not been altered.

### 6.3 Decision Trace

The decision trace is an ordered list of every policy rule evaluated during the policy stage:

```json
[
  {
    "rule_description": "[MANDATORY] Malware not detected",
    "condition": "MalwareDetected",
    "matched": false,
    "verdict": null
  },
  {
    "rule_description": "Signature verified (policy requires it)",
    "condition": "SignatureRequired",
    "matched": true,
    "verdict": "Verified"
  }
]
```

Every rule is listed — whether matched or not — providing a complete audit trail of the policy evaluation logic for every run.

### 6.4 Policy Digest

The policy digest is the SHA-256 of the canonical JSON serialization of the policy document. It is included in the JSON report (`policy.digest`) and in the policy stage evidence item. This allows an auditor to:

1. Verify that the exact policy text used for a run is on file.
2. Detect if a policy file was modified between verification and audit.
3. Correlate multiple reports to confirm they used the same policy.

### 6.5 Report Schema Stability

The JSON report schema is versioned (`schema_version: "1.0"`). The schema is designed to be additive: new fields may be added in future versions, but existing fields will not be removed, renamed, or have their types changed. This ensures that consumers of the report will not break when veriscan is updated.

---

## 7. Offline Verification Bundles

### 7.1 The Air-Gap Problem

Air-gapped environments require that all software be physically transferred from a connected staging environment to the isolated network. The challenge is ensuring:
1. The artifact transferred matches the artifact approved in the connected environment.
2. All verification evidence accompanies the artifact so that in-environment re-verification is possible.
3. The in-environment verification does not require network access.
4. The verification evidence cannot be forged during the physical transfer.

### 7.2 Bundle Structure

An offline verification bundle is a directory containing all artifacts and metadata needed for complete offline verification:

```
bundle/
  artifact.tar.gz            # The artifact
  artifact.tar.gz.sha256     # Hex SHA-256 checksum
  artifact.tar.gz.sha512     # Hex SHA-512 checksum
  artifact.tar.gz.sig        # PGP detached signature over artifact
  trusted_keys/
    vendor_signing_key.asc   # Trusted public key(s)
  bundle.manifest.json       # Lists all bundle files with SHA-256 hashes
  bundle.manifest.sig        # PGP detached signature over the manifest
```

The `bundle.manifest.json` lists every file in the bundle with its individual SHA-256 hash. The manifest is signed with a PGP key whose public counterpart is included in the `trusted_keys/` directory.

### 7.3 Bundle Verification Protocol

The protocol is ordered to minimize trust in any content before it has been authenticated:

1. Load trusted keys from `trusted_keys/` — if none found, fail immediately.
2. Verify `bundle.manifest.sig` over `bundle.manifest.json` — this step must succeed before any other file is trusted.
3. Parse manifest and verify SHA-256 of every listed file — a mismatch on any file fails immediately.
4. Run the full pipeline on the verified artifact — in offline mode, reputation degrades gracefully.

### 7.4 Path Traversal Protection

The `safe_bundle_path` function rejects any manifest entry whose relative path starts with `/` (absolute path) or contains `..` (parent directory traversal). A malicious manifest cannot direct file operations outside the bundle directory.

### 7.5 Why Bundles Matter

| Without offline bundles | With offline bundles |
|------------------------|----------------------|
| Artifact transferred with no verification metadata | Artifact, checksums, signatures, and trusted keys travel as a sealed unit |
| Re-verification in air-gap requires manual reconstruction | Re-verification is fully automated and self-contained |
| No cryptographic evidence that transferred artifact matches approved artifact | Manifest signature provides cryptographic chain of custody |
| Policy and key configuration may differ from connected environment | Bundle carries its own trusted keys; policy is specified per environment |

---

## 8. Policy Engine Rationale

### 8.1 Rule-Based, Not Heuristic

The policy engine is purely rule-based. Every decision rule maps a discrete, observable pipeline outcome to a verdict. There are no probabilistic scores, machine learning models, or heuristic aggregations. Conditions available to policy rules include:

| Condition | Observable State |
|-----------|-----------------|
| `MalwareDetected` | ClamAV detected malware |
| `SignatureMissing` | No signature file found |
| `SignatureInvalid` | Cryptographic verification failed |
| `SignerNotAllowed` | Valid signature from unauthorized signer |
| `ChecksumMismatch` | Computed hash does not match expected |
| `HighEntropy` | Shannon entropy exceeds threshold |
| `DeniedFileType` | File type in denylist |
| `ReputationMalicious` | VT flagged artifact as malicious |
| `ReputationUnavailable` | VT result not available |
| `MalwareScanUnavailable` | ClamAV not found or failed |
| `SbomMissing` | `require_sbom` enabled but no SBOM |
| `Always` | Unconditional (fallback/default rules) |

### 8.2 First-Match Semantics

Rules in the `decision_matrix` are evaluated in declaration order. The first matching rule wins. This makes rule priority explicit — an operator can reason about policy behavior by reading rules top to bottom.

### 8.3 Mandatory Hardwired Checks

Two conditions are hardwired as always-fatal and cannot be overridden:

1. `MalwareResult::Detected` → always `FAILED`.
2. `ReputationResult::Malicious` → always `FAILED`.

There is no policy configuration, no matter how permissive, that allows a malware-positive or reputation-malicious artifact to receive a `VERIFIED` verdict.

### 8.4 Policy Validation at Load Time

Policies are validated before any verification begins. Invalid policies cause veriscan to exit with code 99 (tool error). Validation checks include: non-empty `name`; `max_entropy_threshold` in [0.0, 8.0]; `allow_signers` entries are valid 40-hex or 64-hex strings.

### 8.5 Rationale for Policy-as-Code

Encoding verification requirements in a versioned YAML file provides compliance advantages:

- **Auditability:** The policy file can be reviewed, approved, and version-controlled.
- **Reproducibility:** Given the same policy, artifact, and verification environment, the result is deterministic.
- **Change management:** Policy changes are tracked; before/after policy digest comparison supports documentation.
- **Environment tiering:** Different policies express different assurance levels without code changes.

---

## 9. Mapping to NIST 800-53 Rev 5 and NIST 800-161

### 9.1 NIST SP 800-53 Rev 5 Control Mapping

| Control | Title | veriscan Alignment |
|---------|-------|-------------------|
| CM-3 | Configuration Change Control | Hash verification; policy digest tracks policy changes |
| CM-4 | Impact Analysis | Static inspection; reputation lookup; entropy flagging |
| CM-7 | Least Functionality | `deny_file_types`; `executable_handling`; URL denylist |
| CM-14 | Signed Components | PGP signature verification; `allow_signers` fingerprint pinning |
| SI-2 | Flaw Remediation | ClamAV malware scan; VirusTotal reputation check |
| SI-3 | Malware Protection | Hardened ClamAV subprocess; bounded output; timeout |
| SI-7 | Software, Firmware, and Information Integrity | SHA-256/512; PGP; inter-stage mutation detection; bundle manifests |
| SI-10 | Information Input Validation | Policy validation; path traversal prevention; input bounds |
| SA-8 | Security Engineering Principles | Fail-closed; typed errors; defense in depth; no execution |
| SA-9 | External System Services | Hash-only VT queries; TLS; graceful degradation |
| SA-10 | Developer Configuration Management | Policy version + digest in every report |
| SA-15 | Development Process, Standards, Tools | Rust memory safety; `cargo audit`; test suite |
| AU-2 | Event Logging | Structured JSON tracing on all pipeline events |
| AU-3 | Content of Audit Records | `run_id`, `timestamp`, verdict, evidence chain in every report |
| AU-9 | Protection of Audit Information | Evidence `deterministic_id`; atomic report writes |
| AU-12 | Audit Record Generation | Complete decision trace per run |

### 9.2 NIST SP 800-161 Rev 1 C-SCRM Mapping

| C-SCRM Area | veriscan Capability |
|-------------|---------------------|
| Provenance verification | PGP signature + fingerprint pinning; checksum verification |
| Component integrity | SHA-256/512 multi-point verification; inter-stage mutation detection |
| Tamper protection in transit | Offline bundle: manifest signature + per-file hash |
| Threat intelligence integration | VirusTotal hash-only lookup; locally cached for resilience |
| Risk-tiered configurations | Four reference policies for different assurance levels |
| Air-gapped operations | Offline bundle format with complete self-contained verification |
| Evidence for SCRM audits | JSON report with full evidence chain; policy digest |

> **Note:** The NIST control mappings describe alignment and support. They do not constitute automatic satisfaction of controls. Each control must be evaluated in the context of the complete system, organizational policies, and operational procedures.

---

## 10. Limitations and Assumptions

### 10.1 Technical Limitations

**Zero-day malware:** ClamAV is signature-based. Novel malware without existing signatures will not be detected. Static inspection provides supplementary indicators but does not substitute for behavioral analysis.

**Signed malicious content:** veriscan verifies that an artifact is signed by a trusted key. It cannot verify that the key holder has not been compromised or has not intentionally signed malicious content. `VERIFIED` does not mean safe — it means the artifact passed the configured checks.

**VirusTotal coverage gaps:** No database has complete coverage. Newly-discovered malware, targeted malware designed to evade common engines, and specialized implants may not appear in VT results.

**SBOM enforcement is Phase II:** The `require_sbom` policy flag currently produces `UNVERIFIED` when set to `true`. Full SBOM verification is a planned future capability.

**No behavioral analysis:** veriscan performs static inspection only. Artifacts that download and execute a secondary payload at runtime, or that contain time-delayed execution logic, cannot be detected by static analysis alone.

### 10.2 Operational Assumptions

**Verification environment integrity:** The host running veriscan must be trusted. A compromised verification host can produce false verification records regardless of the tool's design.

**Key management is external:** The security of signature verification depends on the security of key management processes that produce and protect signing keys.

**ClamAV database currency:** Malware scan quality depends on the recency of the ClamAV signature database. veriscan does not update ClamAV databases.

**Policy files are access-controlled:** An attacker who can modify a policy file can weaken verification requirements. Policy files must be treated as security-sensitive configuration.

---

## 11. Operational Guidance

### 11.1 Deployment in a SOC Environment

Recommended configuration: `contractor_strict.yaml` or a hardened customization.

**Workflow:**

1. Configure the trusted keys directory with public keys of approved software vendors.
2. Populate `allow_signers` with the fingerprints of each vendor's signing key.
3. Configure the ClamAV path and ensure the database is updated on schedule.
4. Set `VT_API_KEY` in the environment for reputation lookups.
5. For each incoming artifact:

```bash
veriscan verify \
    --policy /etc/veriscan/contractor_strict.yaml \
    --trusted-keys /etc/veriscan/trusted_keys/ \
    --sig artifact.tar.gz.asc \
    --report-json /var/log/veriscan/$(date +%Y%m%d)-$(basename artifact.tar.gz).json \
    --report-md /var/log/veriscan/$(date +%Y%m%d)-$(basename artifact.tar.gz).md \
    /path/to/artifact.tar.gz
```

6. Exit code 0: proceed to staging. Exit code 10 or 20: hold for analyst review.
7. Archive the JSON report in the change management system alongside the approval record.

### 11.2 Deployment in CI/CD Pipelines

Recommended configuration: `ci_gate.yaml`

**Exit code contract:**

| Exit Code | Meaning | CI Action |
|-----------|---------|-----------|
| 0 | VERIFIED — all required checks passed | Continue pipeline |
| 10 | UNVERIFIED — checks incomplete | Warn; operator decides |
| 20 | FAILED — definitive failure | Block; do not deploy |
| 99 | Tool error — policy invalid, I/O failure | Investigate configuration |

**GitHub Actions integration example:**

```yaml
jobs:
  verify-artifact:
    runs-on: ubuntu-latest
    steps:
      - name: Download artifact
        run: curl -LO https://releases.example.com/tool-3.2.1.tar.gz

      - name: Verify artifact
        env:
          VT_API_KEY: ${{ secrets.VT_API_KEY }}
        run: |
          veriscan verify \
            --policy ci_gate.yaml \
            --expected-sha256 ${{ vars.TOOL_SHA256 }} \
            --trusted-keys trusted_keys/ \
            --sig tool-3.2.1.tar.gz.asc \
            --report-json reports/tool-3.2.1-verify.json \
            tool-3.2.1.tar.gz

      - name: Upload verification report
        uses: actions/upload-artifact@v4
        with:
          name: verification-report
          path: reports/
```

### 11.3 Air-Gapped Operations

**Phase 1 — Bundle creation (connected environment):**

```bash
veriscan bundle create \
    --artifact /staging/vendor-update-3.2.1.tar.gz \
    --keys /etc/veriscan/vendor_keys/ \
    --signing-key /etc/veriscan/approver_secret.asc \
    --out /media/transfer/vendor-update-bundle/
```

**Phase 2 — Physical transfer:** Transfer the bundle directory via approved removable media.

**Phase 3 — Verification in air-gapped environment:**

```bash
veriscan verify \
    --policy /etc/veriscan/airgapped.yaml \
    --offline /mnt/transfer/vendor-update-bundle/ \
    --report-json /var/log/veriscan/$(date +%Y%m%d)-vendor-update.json
```

### 11.4 Hardening Recommendations

| Recommendation | Rationale |
|----------------|-----------|
| Always populate `allow_signers` in production policies | Prevents acceptance of arbitrary signed artifacts |
| Set `malware_failure_is_fatal: true` in high-assurance policies | Ensures malware scan is not silently skipped |
| Set `require_checksums: true` | Ensures expected checksums are always verified |
| Write reports to append-only or WORM storage | Protects audit records from tampering |
| Verify JSON reports with an additional GPG signature post-generation | Provides non-repudiation for the verification record |
| Run `cargo audit` on veriscan itself before deployment | Ensures the verification tool has no known-vulnerable dependencies |
| Verify the veriscan binary SHA-256 before deployment | Applies the same supply chain verification to the verification tool |

---

## 12. Future Work

### 12.1 SBOM Enforcement

The `require_sbom` policy flag currently generates `UNVERIFIED` as a placeholder. Full SBOM enforcement will:
- Accept SPDX and CycloneDX SBOM formats.
- Verify the SBOM's digital signature.
- Validate that the SBOM references the artifact being verified by hash.
- Optionally query NVD or OSV against SBOM components.
- Produce component-level evidence items for each SBOM entry.

### 12.2 Reproducible Build Verification

Integration with reproducible build workflows will allow veriscan to verify that a given artifact binary can be reproduced from published source code. This addresses the compiler/toolchain supply chain attack vector currently outside the threat model. The planned approach invokes a containerized build, compares the produced artifact's hash to the distributed artifact's hash, and records build environment details in the evidence chain.

### 12.3 TPM/HSM Integration

For environments with Trusted Platform Modules (TPM) or Hardware Security Modules (HSM):
- HSM-backed signing of verification reports for non-repudiation.
- TPM-based attestation of the verification environment, binding reports to a specific attested host.
- HSM-stored trusted keys, eliminating filesystem-based key exposure.

### 12.4 Extended Reputation Sources

The reputation stage currently supports VirusTotal. Planned additions:
- CIRCL hash lookup (`hashlookup.circl.lu`).
- AlienVault OTX indicator lookup.
- Custom internal threat intelligence feeds via a configurable API endpoint.

### 12.5 Policy Language Extensions

Planned extensions to the condition DSL:
- AND/OR compound rule conditions.
- Threshold rules (e.g., `reputation.engines_detected > 3`).
- Custom indicator rules with user-defined regular expressions.

### 12.6 Report Signing and Notarization

Planned features for report integrity:
- Built-in GPG signing of JSON reports at generation time.
- Optional RFC 3161 timestamping via a trusted timestamp authority.
- Merkle tree-based batch notarization for high-volume environments.

---

## Appendix A: Example JSON Report Structure

The following is an abbreviated example of a veriscan JSON report for a successfully verified artifact. Note the high-entropy flag: GZIP archives have high entropy by nature (compressed content), so `entropy_flagged: true` is expected and the decision trace shows the `HighEntropy -> Unverified` rule was evaluated but did not produce a final failure because the overall verdict is determined by the most severe matching condition.

```json
{
  "schema_version": "1.0",
  "run_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "timestamp": "2026-02-25T14:30:00.000Z",
  "elapsed_secs": 3.42,
  "artifact": {
    "source": "https://releases.example.com/tool-3.2.1.tar.gz",
    "filename": "tool-3.2.1.tar.gz",
    "size_bytes": 8372941
  },
  "verdict": {
    "status": "VERIFIED",
    "reason": null,
    "exit_code": 0
  },
  "hashes": {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "sha256_verified": true,
    "sha512_verified": true
  },
  "signature": {
    "status": "verified",
    "signer_uid": "Example Vendor Release Key <releases@example.com>",
    "fingerprint": "AABBCCDDEEFF00112233445566778899AABBCCDD",
    "detail": null
  },
  "malware_scan": {
    "status": "clean",
    "engine": "ClamAV",
    "engine_version": "ClamAV 1.3.0",
    "detections": []
  },
  "reputation": {
    "status": "clean",
    "engines_total": 72,
    "engines_detected": 0,
    "source": "VirusTotal",
    "last_seen": "2026-02-24T10:00:00Z",
    "link": "https://www.virustotal.com/gui/file/e3b0c44..."
  },
  "inspection": {
    "file_type": "GZIP",
    "entropy": 7.89,
    "entropy_flagged": true,
    "indicators": [],
    "is_executable": false,
    "is_script": false
  },
  "policy": {
    "name": "contractor_strict",
    "version": "1.0",
    "digest": "8f14e45fceea167a5a36dedd4bea2543c3d399b1ca2ab7e2b7da2ab7e2b7da2a"
  },
  "decision_trace": [
    {
      "rule_description": "[MANDATORY] Malware not detected",
      "condition": "MalwareDetected",
      "matched": false,
      "verdict": null
    },
    {
      "rule_description": "[MANDATORY] Reputation not malicious",
      "condition": "ReputationMalicious",
      "matched": false,
      "verdict": null
    },
    {
      "rule_description": "Checksum mismatch",
      "condition": "ChecksumMismatch",
      "matched": false,
      "verdict": null
    },
    {
      "rule_description": "Signature verified (policy requires it)",
      "condition": "SignatureRequired",
      "matched": true,
      "verdict": "Verified"
    },
    {
      "rule_description": "High entropy: artifact may be packed or encrypted",
      "condition": "HighEntropy",
      "matched": true,
      "verdict": "Unverified"
    }
  ],
  "evidence": [
    {
      "timestamp": "2026-02-25T14:29:57.123Z",
      "stage_name": "acquire",
      "inputs": {
        "source": "https://releases.example.com/tool-3.2.1.tar.gz"
      },
      "outputs": {
        "filename": "tool-3.2.1.tar.gz",
        "size_bytes": 8372941,
        "initial_sha256": "e3b0c44298fc1c..."
      },
      "tool_versions": {},
      "deterministic_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    }
  ],
  "tool_versions": {},
  "warnings": []
}
```

---

## Appendix B: Example Policy YAML Snippet

The following is the `contractor_strict.yaml` policy, representing the highest-assurance pre-built policy included with veriscan:

```yaml
# Veriscan Contractor-Strict Policy
# High-assurance policy for defense contractor environments.

name: "contractor_strict"
version: "1.0"

require_signature: true
allow_unsigned: false
allow_network: true
require_checksums: true
require_sbom: false

reputation_required: true
reputation_failure_is_fatal: false

malware_scan_required: true
malware_failure_is_fatal: false

deny_file_types: []

# MUST be populated before production deployment
# Example: "AABBCCDD..." (40-hex PGP v4 fingerprint)
allow_signers: []

max_entropy_threshold: 7.0
url_patterns_denylist:
  - "http://"

executable_handling: "block_unsigned"

network_timeout_seconds: 30
subprocess_timeout_seconds: 120
max_subprocess_output_bytes: 65536

max_inspection_strings: 2000
min_string_length: 6
entropy_sample_bytes: 1048576

vt_api_key_env: "VT_API_KEY"
reputation_cache_dir: "/var/cache/veriscan/reputation"
reputation_cache_ttl_seconds: 3600

decision_matrix:
  - description: "Malware detected"
    condition:
      type: "malware_detected"
    verdict: "failed"

  - description: "Reputation: artifact flagged as malicious"
    condition:
      type: "reputation_malicious"
    verdict: "failed"

  - description: "Checksum mismatch"
    condition:
      type: "checksum_mismatch"
    verdict: "failed"

  - description: "Signer not in allowlist"
    condition:
      type: "signer_not_allowed"
    verdict: "failed"

  - description: "Signature invalid"
    condition:
      type: "signature_invalid"
    verdict: "failed"

  - description: "Signature missing (required)"
    condition:
      type: "signature_missing"
    verdict: "failed"

  - description: "File type denied"
    condition:
      type: "denied_file_type"
    verdict: "failed"

  - description: "High entropy: artifact may be packed or encrypted"
    condition:
      type: "high_entropy"
    verdict: "unverified"
```

**Before production deployment:**
- Populate `allow_signers` with full 40-hex fingerprints of approved signing keys.
- Set `malware_failure_is_fatal: true` for environments where ClamAV is guaranteed present.
- For air-gapped environments, use `airgapped.yaml` which sets `allow_network: false`.

---

## Appendix C: Example Evidence Item

The following is a complete evidence item from the `hash` stage of a verification run:

```json
{
  "timestamp": "2026-02-25T14:29:57.841Z",
  "stage_name": "hash",
  "inputs": {
    "artifact_path": "/tmp/veriscan_staging/tool-3.2.1.tar.gz",
    "expected_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "outputs": {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "sha256_matched": true
  },
  "tool_versions": {},
  "deterministic_id": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
}
```

**Evidence item field reference:**

| Field | Value | Purpose |
|-------|-------|---------|
| `timestamp` | ISO 8601 UTC | When this evidence was collected |
| `stage_name` | `"hash"` | Which pipeline stage produced this item |
| `inputs.artifact_path` | File path | The artifact that was hashed |
| `inputs.expected_sha256` | Hex string | Expected hash for comparison |
| `outputs.sha256` | Hex string | SHA-256 computed from artifact bytes |
| `outputs.sha512` | Hex string | SHA-512 computed from artifact bytes |
| `outputs.sha256_matched` | `true` | Computed SHA-256 matched expected value |
| `tool_versions` | `{}` | No external tools; pure-Rust hash computation |
| `deterministic_id` | Hex string | SHA-256 of canonical serialization of this entire item |

**Verifying the deterministic_id independently:**

The canonical serialization format is:
```
stage:<stage_name>|timestamp:<timestamp>|in:<key1>=<val1>|in:<key2>=<val2>|out:<key1>=<json_val1>|out:<key2>=<json_val2>
```

Keys within each section are sorted lexicographically. The SHA-256 of this canonical string should match the `deterministic_id` in the report. Any discrepancy indicates the evidence record was modified after generation.

---

*veriscan is maintained as an open-source project dual-licensed under MIT and Apache 2.0. This whitepaper describes version 0.1.0 of the tool. For integration guidance, see the demo scripts in `demo/scripts/`. For the full threat model, see `docs/threat_model.md`.*

