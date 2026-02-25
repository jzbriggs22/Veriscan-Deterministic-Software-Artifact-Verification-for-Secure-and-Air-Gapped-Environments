# NIST SP 800-53 Rev 5 Control Mapping

**veriscan** implements or supports the following NIST SP 800-53 Revision 5 controls:

---

## SA — System and Services Acquisition

### SA-12: Supply Chain Risk Management
**Control**: Protect against supply chain risks by employing security safeguards as part of a comprehensive defense-in-depth information security strategy.

**veriscan mapping**:
- Mandatory pipeline enforces cryptographic integrity verification (Hash stage) before any other processing
- PGP signature verification (Signature stage) validates artifact authenticity and chain of custody
- Policy engine enforces configurable risk acceptance criteria
- Structured evidence and audit trails document the verification decision and rationale
- Offline bundle format enables secure artifact transfer in air-gapped environments

### SA-12(1): Acquisition Strategies / Tools / Methods
**veriscan mapping**: Provides standardized artifact intake tooling with machine-readable output for integration into acquisition workflows.

### SA-12(7): Processes to Address Weaknesses or Deficiencies
**veriscan mapping**: Policy configuration allows organizations to enforce stricter controls (e.g., `contractor_strict.yaml`) based on supplier risk assessments.

### SA-12(10): Validate as Genuine and Not Altered
**veriscan mapping**: Hash stage computes and verifies SHA-256/SHA-512; signature stage verifies PGP authenticity; bundle manifest verification prevents transit tampering.

---

## SI — System and Information Integrity

### SI-7: Software, Firmware, and Information Integrity
**Control**: Employ integrity verification tools to detect unauthorized changes to software, firmware, and information.

**veriscan mapping**:
- SHA-256 and SHA-512 hash verification detects any bit-level modification
- Mutation detection: artifact hash recomputed after each pipeline stage to detect in-pipeline tampering
- PGP signature verification proves the artifact originates from a known, trusted signer
- Evidence `deterministic_id` provides tamper-evident evidence records

### SI-7(1): Integrity Checks
**veriscan mapping**: Integrity checks performed at acquire time and after each pipeline stage. Hash mismatch produces immediate FAILED verdict.

### SI-7(2): Automated Notifications of Integrity Violations
**veriscan mapping**: Exit code 20 (FAILED) enables automated CI/CD pipeline blocking. JSON reports are machine-parseable for SIEM integration.

### SI-7(6): Cryptographic Protection
**veriscan mapping**: SHA-256, SHA-512 for integrity; PGP (Ed25519/RSA) for authenticity. All crypto operations use vetted implementations (sha2 crate, sequoia-openpgp).

### SI-3: Malicious Code Protection
**Control**: Implement malicious code protection mechanisms.

**veriscan mapping**: ClamAV integration provides signature-based malware detection before artifact is used in any system. Malware detection always produces FAILED verdict regardless of other results.

---

## AU — Audit and Accountability

### AU-2: Event Logging
**Control**: Identify the types of events that the system is capable of logging.

**veriscan mapping**: Every pipeline stage produces structured `EvidenceItem` records with timestamp, inputs, outputs, and tool versions. All decisions are logged in the `decision_trace`.

### AU-9: Protection of Audit Information
**Control**: Protect audit information from unauthorized access, modification, and deletion.

**veriscan mapping**:
- Evidence items use SHA-256 `deterministic_id` for tamper detection
- Reports written atomically (temp file + rename) to prevent partial writes
- Append-only evidence chain: no stage can modify evidence from prior stages
- Audit log path configurable via `--audit-log` CLI flag

### AU-10: Non-repudiation
**Control**: Provide irrefutable evidence that an individual took a specific action.

**veriscan mapping**:
- PGP signature evidence records the signing key fingerprint and signer UID
- Policy digest cryptographically binds verdict to exact policy version
- Correlation ID (`run_id`) links all evidence from a single verification run
- Structured JSON reports can be signed by CI/CD systems for non-repudiation

### AU-12: Audit Record Generation
**veriscan mapping**: Every run generates a complete JSON report containing all evidence items, decision trace, tool versions, and verdict — constituting a complete audit record.

---

## CM — Configuration Management

### CM-14: Signed Components
**Control**: Prevent the installation of software without verification that the component has been digitally signed.

**veriscan mapping**: With `require_signature: true` and `allow_unsigned: false` in policy (as in `contractor_strict.yaml`), any artifact without a valid PGP signature receives FAILED verdict, blocking installation.

### CM-3: Configuration Change Control
**veriscan mapping**: Policy YAML files are version-controlled with SHA-256 digest. Every report includes the policy digest, enabling audit of which policy version authorized each artifact.

---

## RA — Risk Assessment

### RA-5: Vulnerability Monitoring and Scanning
**veriscan mapping**: VirusTotal reputation lookup cross-references artifact hash against known threat intelligence from 70+ antivirus engines. Result included in structured evidence.

---

## SC — System and Communications Protection

### SC-28: Protection of Information at Rest
**veriscan mapping**: API keys (VirusTotal) are read from environment variables only, never stored on disk. Reputation cache stores only hash lookups, never file content.

---

## Summary Table

| Control | Family | Status | Implementation |
|---------|--------|--------|---------------|
| SA-12 | Supply Chain | Implemented | Hash + Signature + Policy stages |
| SA-12(1) | Supply Chain | Implemented | Standardized CLI with machine output |
| SA-12(7) | Supply Chain | Implemented | Configurable policy engine |
| SA-12(10) | Supply Chain | Implemented | Hash + Signature verification |
| SI-7 | Integrity | Implemented | SHA-256/512, PGP, mutation detection |
| SI-7(1) | Integrity | Implemented | Per-stage integrity checks |
| SI-7(2) | Integrity | Implemented | Exit codes + JSON output for SIEM |
| SI-7(6) | Integrity | Implemented | sha2, sequoia-openpgp |
| SI-3 | Malware | Implemented | ClamAV integration |
| AU-2 | Audit | Implemented | EvidenceItem per stage |
| AU-9 | Audit | Implemented | Deterministic IDs, atomic writes |
| AU-10 | Audit | Implemented | PGP fingerprint, policy digest, run_id |
| AU-12 | Audit | Implemented | Complete JSON audit report |
| CM-14 | Config Mgmt | Implemented | require_signature policy |
| CM-3 | Config Mgmt | Implemented | Policy version + digest |
| RA-5 | Risk | Implemented | VirusTotal reputation lookup |
| SC-28 | SC Protection | Implemented | API keys env-only, no disk storage |

