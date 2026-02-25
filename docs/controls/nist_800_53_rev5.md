# NIST SP 800-53 Rev 5 Control Mapping

## Veriscan Alignment with NIST SP 800-53 Rev 5

**Version:** 1.0

---

## Disclaimer

This document describes how Veriscan's technical controls align with selected NIST SP 800-53 Revision 5 security controls. This alignment mapping is informational and does not constitute a formal assessment, audit finding, or certification claim. Veriscan is a verification tool; its contribution to any organization's overall control posture depends on how it is deployed, configured, and integrated with the broader information security program.

Organizations seeking FedRAMP Authorization, FISMA compliance, or DoD RMF approval must conduct their own control assessments in accordance with applicable guidance. The mappings below are intended to assist security assessors in understanding where Veriscan's features contribute to control satisfaction — not to substitute for that assessment.

---

## Mapping Methodology

Each row in the tables below identifies:

- **Control ID** — the NIST SP 800-53 Rev 5 control identifier.
- **Control Name** — the official control name.
- **Veriscan Feature** — the specific veriscan capability or behavior that contributes to this control.
- **Evidence Output** — the field(s) in the JSON report or evidence array that document this control's operation.
- **Notes** — limitations, assumptions, or additional context.

---

## CM — Configuration Management

| Control ID | Control Name | Veriscan Feature | Evidence Output | Notes |
|---|---|---|---|---|
| CM-3 | Configuration Change Control | Policy digest binding ensures every verification run records the exact policy configuration in effect. Changes to policy files are detectable by comparing digest values across runs. The `policy-validate` subcommand prints the digest of any policy file on demand. | `report.policy.digest` (SHA-256 of serialized policy) | Policy file change management (version control, peer review) is the operator's responsibility. Veriscan records but does not enforce policy change controls. |
| CM-6 | Configuration Settings | Four reference policy profiles (`default`, `contractor_strict`, `airgapped`, `ci_gate`) encode security-relevant configuration settings for different deployment contexts. Policy validation (`veriscan policy-validate`) verifies settings conform to the schema before use. Invalid settings produce exit code 99 without executing verification. | `report.policy.name`, `report.policy.version`, `report.policy.digest` | Policy files must be stored and controlled in accordance with the organization's CM baseline. |
| CM-7 | Least Functionality | The `deny_file_types` policy field and `executable_handling: deny_all` option restrict which artifact types are permitted into the controlled environment. Artifacts of denied types produce a FAILED verdict (exit code 20). The `url_patterns_denylist` restricts artifact acquisition sources. | `report.inspection.file_type`, `report.verdict`, `evidence[].outputs.file_type` for the inspect stage | Least functionality at the artifact intake level. Does not control system-level functionality of deployed software; that requires additional runtime controls. |
| CM-14 | Signed Components | PGP detached signature verification (Stage 3) verifies that artifacts were signed by an authorized party before admission. Signer fingerprint pinning (`allow_signers` list) ensures only pre-approved signing keys are accepted. With `require_signature: true`, unsigned artifacts produce FAILED verdict. | `report.signature.status`, `report.signature.fingerprint`, `report.signature.signer_uid`, `evidence[].outputs.signature_status` for the signature stage | CM-14 intent: prevent installation of software without verification of digital signature. Veriscan enforces this at artifact intake. Runtime enforcement requires integration with the deployment pipeline so that only VERIFIED artifacts proceed to installation. |

---

## SI — System and Information Integrity

| Control ID | Control Name | Veriscan Feature | Evidence Output | Notes |
|---|---|---|---|---|
| SI-3 | Malware Protection | ClamAV subprocess integration (Stage 4) scans artifacts for known malware signatures before admission to any controlled environment. Malware detection is a mandatory hard-fail condition: it cannot be overridden by any policy configuration. The ClamAV engine version is recorded in evidence for audit reproducibility. | `report.malware_scan.status`, `report.malware_scan.engine`, `report.malware_scan.engine_version`, `report.malware_scan.detections`, `evidence[].outputs.scan_status` for the malware stage | SI-3 covers malware protection throughout the system lifecycle. Veriscan addresses the artifact intake control point. ClamAV definition currency is the deploying organization's responsibility. Novel malware not in the signature database will not be detected by this stage alone. |
| SI-3(1) | Malware Protection — Central Management | Policy files centrally define malware scanner path, timeout, output bound, and required/fatal flags. All veriscan instances using the same policy file share identical malware control configuration. Policy digest binding ensures configuration cannot drift silently. | `report.policy.digest` confirms policy version; `evidence[].tool_versions.clamscan` records engine version | Centralized policy file distribution and management is the operator's responsibility. |
| SI-7 | Software, Firmware, and Information Integrity | SHA-256 and SHA-512 hash verification (Stage 2) detects unauthorized modification of artifacts. In-pipeline mutation detection (`assert_no_mutation()`) re-verifies SHA-256 after each stage, detecting filesystem-level tampering between stages. Offline bundle manifest signature covers all bundle files. | `report.hashes.sha256`, `report.hashes.sha256_verified`, `report.hashes.sha512_verified`, `evidence[].outputs.sha256` and `sha256_matched` for the hash stage | SI-7 applies to software, firmware, and information during storage and transmission. Veriscan addresses the intake verification point. Ongoing integrity monitoring of already-deployed artifacts requires separate tooling. |
| SI-7(1) | Integrity Checks | Automated integrity checks are performed for every artifact that passes through the veriscan pipeline. The Hash stage is non-bypassable and executes for every run. The `assert_no_mutation()` checks run after every subsequent stage. | `report.hashes.sha256_verified`, `report.hashes.sha512_verified` | Periodic re-verification of already-deployed artifacts is outside veriscan's current scope. |
| SI-7(6) | Cryptographic Protection | SHA-256 and SHA-512 (FIPS 180-4) are used for hash computation via the `sha2` Rust crate. PGP signature verification uses `sequoia-openpgp` with vetted cryptographic implementations. The evidence `deterministic_id` uses SHA-256 for tamper detection. | `report.hashes.sha256`, `report.hashes.sha512`, `report.signature.fingerprint` | The PGP signing algorithm (RSA, Ed25519, ECDSA) depends on the signing key chosen by the artifact publisher. Algorithm selection for signing keys is the signing organization's responsibility. |
| SI-10 | Information Input Validation | Policy files are parsed, schema-validated, and semantically validated (entropy threshold range, fingerprint format) before use. Invalid policy files produce exit code 99 without executing verification. URL inputs are checked against the denylist before any network activity. Bundle path components are validated against traversal patterns. | Exit code 99 on policy validation failure; `VeriError::PolicyInvalid` and `PolicyParseError` documented in source | Input validation covers policy files, URL inputs, and bundle paths. Artifact content is treated as untrusted input throughout the pipeline. |

---

## SA — System and Services Acquisition

| Control ID | Control Name | Veriscan Feature | Evidence Output | Notes |
|---|---|---|---|---|
| SA-8 | Security and Privacy Engineering Principles | Veriscan applies multiple established security engineering principles: fail-closed design (tool absence produces non-pass verdict), no artifact execution (defense-in-depth; static analysis only), typed verification states (prevents boolean confusion at the type level), mandatory pipeline (no bypass paths through any interface), subprocess isolation (cleared environment, absolute path, bounded output, timeout). | Architectural — reflected in all evidence records and exit codes | These are design-time principles baked into the implementation rather than runtime-configurable settings. |
| SA-11 | Developer Testing and Evaluation | Integration test suite (`tests/`) exercises: pipeline stage ordering invariants, in-pipeline mutation detection, offline bundle scenarios (valid, tampered artifact, tampered manifest, missing signature), policy decision matrix evaluation, and JSON report schema stability. `cargo test` executes the full test suite. | Source: `tests/pipeline_invariants.rs`, `tests/offline_bundle.rs`, `tests/policy_decisions.rs`, `tests/report_schema.rs` | SA-11 covers the developer's testing program. Operator acceptance testing and system-level testing in the deployed environment are separate activities not covered by the source test suite. |
| SA-12 | Supply Chain Protection | Veriscan is the primary implementation of software supply chain verification controls. Hash verification, PGP signature verification, malware scanning, static inspection, VirusTotal reputation checking, and YAML policy enforcement together provide layered supply chain controls at artifact intake. | Entire veriscan capability; see all `report.*` fields | SA-12 is the primary NIST 800-53 anchor for supply chain risk management. See also the NIST SP 800-161 Rev 1 mapping in `docs/controls/nist_800_161.md` for dedicated SCRM practice mappings. |
| SA-15 | Development Process, Standards, and Tools | Veriscan is implemented in memory-safe Rust with no unsafe code blocks in the core pipeline. Dependencies are managed via Cargo with pinned versions in `Cargo.lock`. Pure-Rust cryptography (`sequoia-openpgp` with `crypto-rust` feature) eliminates C library supply chain risk. All dependencies are open-source with auditable source code. | `Cargo.toml` (dependency manifest); `Cargo.lock` (pinned versions) | Operators should run `cargo audit` against the dependency manifest to check for known CVEs in crate dependencies. Dependency review is part of supply chain due diligence for the tool itself. |

---

## AU — Audit and Accountability

| Control ID | Control Name | Veriscan Feature | Evidence Output | Notes |
|---|---|---|---|---|
| AU-2 | Event Logging | Every pipeline run generates structured audit events via the `tracing` framework. Events cover: pipeline start/stop, stage completion with outcomes, signature verification results, malware detections, verdict and reason. The `--json-logs` flag enables JSON-structured log output compatible with SIEM ingestion. The `--audit-log` flag appends audit events to a file. | Structured log stream (tracing events with run_id, stage, verdict fields); `report.run_id`, `report.timestamp`, `report.verdict` | Log destination, retention, and SIEM forwarding are the operator's responsibility. The `--json-logs` flag enables structured output suitable for tools such as Splunk, Elastic, or AWS CloudWatch. |
| AU-3 | Content of Audit Records | Every audit event includes: run UUID (`run_id`), timestamp (ISO 8601 UTC), stage name, event type, artifact identifier (SHA-256), and result. The JSON report is a comprehensive audit record covering the full pipeline run including all stage inputs, outputs, tool versions, and the complete decision trace. | `report.run_id`, `report.timestamp`, `report.artifact`, `evidence[].timestamp`, `evidence[].stage_name`, `evidence[].inputs`, `evidence[].outputs`, `report.decision_trace` | AU-3 requires sufficient information to determine event outcome, subject, and object. The JSON report satisfies this requirement for each verification run. |
| AU-9 | Protection of Audit Information | Evidence record integrity is protected by the `deterministic_id` mechanism: each evidence item carries a SHA-256 of its canonical content. Any post-generation modification of evidence fields produces a detectable mismatch. Reports are written atomically (write to temp file, then rename) to prevent partial writes from producing corrupt audit records. | `evidence[].deterministic_id` on each evidence item | Full tamper protection of the report file itself (covering addition/deletion of evidence items) requires external controls: report signing, append-only log systems, or write-once media. See `docs/evidence_model.md` Section 7 for the full tamper detection model. |
| AU-12 | Audit Record Generation | Audit records (evidence items) are generated by every pipeline stage for every run, including runs that terminate early with FAILED verdicts. Evidence generation is not conditional on the verification outcome. The `report.evidence` array is always present in the JSON output. | `report.evidence` array — always present; minimum one item per executed stage; `report.decision_trace` — full policy evaluation trace | A FAILED run produces the same evidence structure as a VERIFIED run for all stages that executed. Stages that did not execute (due to early pipeline termination) do not produce evidence items, which is itself auditable. |

---

## Additional Relevant Controls

| Control ID | Control Name | Veriscan Feature | Evidence Output | Notes |
|---|---|---|---|---|
| AC-4 | Information Flow Enforcement | The `allow_network: false` policy flag prevents outbound network calls. The URL denylist enforces source-based flow control on artifact acquisition. In air-gapped mode, no artifact data or metadata leaves the local host. | Exit code 99 on policy-denied network attempts; `report.policy.name` identifies the policy enforcing flow control | AC-4 is primarily an infrastructure and network control. Veriscan contributes at the artifact verification layer. |
| RA-5 | Vulnerability Monitoring and Scanning | VirusTotal reputation lookup (Stage 6) queries a multi-engine threat intelligence database covering known vulnerability exploits and malware associated with specific file hashes. The query submits only the SHA-256 hash; artifact bytes are not transmitted. | `report.reputation.status`, `report.reputation.engines_total`, `report.reputation.engines_detected`, `report.reputation.source` | RA-5 typically covers system-level vulnerability scanning. Veriscan contributes at the artifact hash reputation level. |
| SR-11 | Component Authenticity | PGP detached signature verification with signer fingerprint pinning provides cryptographic component authenticity assurance at artifact intake. The signer's key fingerprint and user ID are recorded in evidence. | `report.signature.fingerprint`, `report.signature.signer_uid`, `report.signature.status` | SR-11 is a NIST SP 800-161 Rev 1 SCRM control. See `docs/controls/nist_800_161.md` for the full SCRM mapping. |

---

## Implementation Notes for Security Assessors

### What Veriscan Provides

Veriscan provides deterministic, documented evidence of artifact verification at a specific point in time — the artifact intake gate. This evidence is suitable for inclusion in system security documentation, audit packages, and continuous monitoring reports.

### What Veriscan Does Not Provide

- Continuous monitoring of deployed artifacts after admission.
- System-level vulnerability scanning (host, OS, container).
- Network traffic analysis or network-layer access enforcement.
- Signing key management infrastructure or HSM integration.
- ClamAV definition update management.
- Cryptographic signing of report files (requires external controls).
- SBOM verification (Phase II capability, not yet implemented).

### Recommended Configuration for FedRAMP / FISMA Environments

- Use `contractor_strict.yaml` or a custom policy with: `require_signature: true`, `require_checksums: true`, `malware_scan_required: true`, `malware_failure_is_fatal: true`, `reputation_required: true`.
- Populate `allow_signers` with the fingerprints of authorized signing keys.
- Enable `--json-logs` and forward structured logs to the organization's SIEM.
- Store JSON reports in write-once or signed audit log storage.
- Integrate veriscan into the CI/CD pipeline as a mandatory gate: block on exit code 20; investigate exit codes 10 and 99 before proceeding.
- Run `cargo audit` on veriscan dependencies as part of tool supply chain due diligence.
