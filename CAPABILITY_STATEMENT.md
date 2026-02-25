# Capability Statement

## Veriscan — Deterministic Software Artifact Verification for Secure and Air-Gapped Environments

---

## Company Overview

Veriscan is a defense-grade, open-source software artifact verification capability implemented in pure Rust. It provides deterministic, auditable, and cryptographically grounded verification of software artifacts across connected, restricted, and fully air-gapped environments. Every verification decision is backed by structured, tamper-evident evidence suitable for submission to government audit bodies and prime contractor compliance teams.

**NAICS Code:** [TBD by customer organization]

---

## Core Competencies

### Supply Chain Verification
Veriscan addresses the full software supply chain verification lifecycle. Artifacts are verified for integrity (cryptographic hash), authenticity (PGP signature), safety (malware scan), and reputation (hash-only VirusTotal lookup) before they are permitted to enter a staging or deployment environment. No artifact is trusted on provenance alone; every claim is computationally verified.

### Cryptographic Artifact Validation
SHA-256 and SHA-512 digests are computed in a single streaming pass and compared against operator-supplied or adjacent-file expected values. PGP detached signature verification is performed using the `sequoia-openpgp` library — a 100% pure-Rust cryptographic backend — eliminating dependencies on system OpenSSL or GnuPG C libraries. Signer fingerprint pinning enforces that only known, approved keys may sign artifacts admitted to the pipeline.

### Offline and Air-Gapped Verification
Veriscan's offline bundle format packages an artifact, its checksums, its PGP signature, and trusted public keys into a signed, self-verifying directory structure. The bundle manifest is itself PGP-signed; no file within the bundle is trusted until the manifest signature passes. This enables complete verification in networks with no outbound connectivity, including SCIF-class air-gapped environments.

### CI/CD Pipeline Gating
Veriscan is designed as a mandatory gate in automated build and deployment pipelines. Deterministic exit codes (0=VERIFIED, 10=UNVERIFIED, 20=FAILED, 99=tool error) integrate directly with Jenkins, GitLab CI, GitHub Actions, and any shell-based pipeline. The `ci_gate.yaml` policy profile enforces strict verification requirements appropriate for automated gating without human review.

---

## Key Differentiators

| Differentiator | Description |
|---|---|
| **Pure-Rust Implementation** | No C library dependencies. No OpenSSL. No system GnuPG. Reproducible, statically linkable builds. Eliminates entire classes of dependency-chain vulnerabilities. |
| **No Artifact Execution** | The artifact under verification is never executed at any stage. File type, entropy, and indicator analysis are purely static. ClamAV integration reads file bytes through the scanner subprocess; the artifact binary is never invoked. |
| **Mandatory Pipeline** | Stage order (Acquire → Hash → Signature → Malware → Inspect → Reputation → Policy) is hardcoded in the orchestrator. No CLI flag, policy setting, or environment variable can reorder, skip, or short-circuit a stage. |
| **Typed Verification States** | The `VerificationStatus` enum enforces three mutually exclusive outcomes at the Rust type level: `Verified`, `Unverified`, and `Failed`. Boolean confusion errors are structurally impossible. |
| **Audit-Grade Evidence Model** | Every pipeline stage produces an `EvidenceItem` with a deterministic SHA-256 identifier computed from its canonical representation. Evidence records are assembled into the JSON report and can be independently verified for tampering. |
| **In-Pipeline Mutation Detection** | Artifact SHA-256 is recorded immediately after acquisition and re-verified after each subsequent stage. Any mutation of the artifact on disk between stages is an immediate hard `FAILED`. |
| **Fail-Closed Design** | Missing tools, unavailable network services, and configuration gaps produce `UNVERIFIED` or `FAILED` outcomes, never silent pass. Policy controls whether tool absence is `UNVERIFIED` or `FAILED` depending on operational context. |
| **No Secrets in Logs or Config** | API keys are read exclusively from environment variables; they are never written to disk, never serialized into policy files, and never appear in structured log output. Subprocess environments are completely cleared before external tool invocation. |

---

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Implementation Language | Rust (edition 2021) | Memory safety, zero-cost abstractions, no GC pauses |
| PGP Verification | `sequoia-openpgp` (crypto-rust feature) | Pure-Rust OpenPGP; no C library dependency |
| Malware Scanning | ClamAV (`clamscan` subprocess) | Signature-based malware detection |
| Reputation Lookup | VirusTotal v3 API (hash-only) | Known-bad hash detection; artifact bytes never uploaded |
| Hash Algorithms | SHA-256, SHA-512 (`sha2` crate) | Cryptographic integrity verification |
| Policy Engine | YAML policy files + Rust decision matrix evaluator | Declarative, auditable policy enforcement |
| Serialization | `serde` / `serde_json` / `serde_yaml` | Stable JSON report schema, YAML policy parsing |
| Async Runtime | `tokio` | Non-blocking I/O for downloads and subprocess management |
| Structured Logging | `tracing` / `tracing-subscriber` | JSON-structured audit logs; SIEM-compatible |
| Correlation IDs | `uuid` (v4) | Per-run traceability across log streams and reports |
| CLI Framework | `clap` (derive API) | Type-safe CLI argument parsing |
| SBOM Integration | Planned (Phase II) | CycloneDX / SPDX bill-of-materials verification |

---

## Supported Environments

| Environment | Support Level | Notes |
|---|---|---|
| Linux (x86-64, aarch64) | Full | Primary development and deployment target |
| macOS (x86-64, Apple Silicon) | Full | Tested; ClamAV via Homebrew |
| Windows (x86-64) | Documented | Build support; ClamAV path configuration required |
| Air-Gapped (no network) | Full | Offline bundle mode; no external dependencies |
| CI/CD (automated pipelines) | Full | Deterministic exit codes; `ci_gate.yaml` policy |
| Docker / Containerized | Full | Multi-stage Dockerfile provided; ClamAV included |
| SCIF-Class Isolated Networks | Full | Offline bundle workflow; no binary phone-home capability |

---

## Security Posture

- **No artifact execution at any stage** — static analysis only
- **Subprocess isolation** — ClamAV invoked via absolute path only; environment cleared before invocation; stdout/stderr bounded
- **Fail-closed defaults** — tool absence and network unavailability are surfaced as non-passing verdicts
- **No sensitive data in reports or logs** — API keys, environment secrets, and key material are excluded from all outputs
- **Path traversal prevention** — bundle verification canonicalizes paths and rejects `../` sequences
- **Policy digest in every report** — auditors can verify the exact policy under which a verdict was reached
- **Deterministic evidence IDs** — SHA-256 over canonical evidence representation enables downstream tamper detection

---

## Deliverables

| Deliverable | Description |
|---|---|
| `veriscan` binary | Compiled CLI tool (Linux/macOS/Windows) |
| Policy files | `default.yaml`, `contractor_strict.yaml`, `airgapped.yaml`, `ci_gate.yaml` |
| JSON report schema | Stable v1.0 schema; documented via `veriscan report-schema` |
| Markdown report | Human-readable verification summary |
| Demo scripts | Online and offline demo scenarios with expected outputs |
| Docker demo environment | Self-contained ClamAV + GPG demo container |
| Architecture documentation | `docs/architecture.md` |
| Threat model | `docs/threat_model.md` |
| Evidence model | `docs/evidence_model.md` |
| Demo guide | `docs/demo_guide.md` |
| NIST SP 800-53 Rev 5 control mapping | `docs/controls/nist_800_53_rev5.md` |
| NIST SP 800-161 Rev 1 SCRM mapping | `docs/controls/nist_800_161.md` |
| Compliance matrix (CSV) | `docs/controls/compliance_matrix.csv` |

---

## NIST Framework Alignment

Veriscan's verification controls are mapped to NIST SP 800-53 Rev 5 and NIST SP 800-161 Rev 1 (Supply Chain Risk Management). Key control families addressed include:

- **CM (Configuration Management):** CM-3, CM-6, CM-7, CM-14
- **SI (System and Information Integrity):** SI-3, SI-7, SI-10
- **SA (System and Services Acquisition):** SA-8, SA-11, SA-12, SA-15
- **AU (Audit and Accountability):** AU-2, AU-3, AU-9
- **SR (Supply Chain Risk Management):** SR-3, SR-4, SR-6, SR-11

Full control mapping tables are available in `docs/controls/`.

---

## Past Performance

[To be populated by customer organization]

---

## Contact Information

[To be populated by customer organization]

---

*Veriscan is dual-licensed under MIT and Apache 2.0. It does not execute artifacts and never uploads file content to external services.*
