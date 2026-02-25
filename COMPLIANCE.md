# Compliance Posture — veriscan

**Version:** 1.0
**Last updated:** 2026-02-25
**Framework versions referenced:** NIST SP 800-53 Rev 5, NIST SP 800-161 Rev 1

> **Important notice:** veriscan does not hold any compliance certification and does not claim conformance to any regulatory framework. This document describes how veriscan's design and outputs *align with* and *support* specific control families. The presence of veriscan in a system's security stack does not by itself satisfy any control; each control must be evaluated in the context of the broader system, organizational policies, and operational procedures.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [NIST SP 800-53 Rev 5 Control Mapping](#2-nist-sp-800-53-rev-5-control-mapping)
3. [NIST SP 800-161 Rev 1 SCRM Mapping](#3-nist-sp-800-161-rev-1-scrm-mapping)
4. [Evidence Produced by veriscan](#4-evidence-produced-by-veriscan)
5. [Limitations — What veriscan Does Not Claim](#5-limitations--what-veriscan-does-not-claim)
6. [Using veriscan Evidence in a Compliance Package](#6-using-veriscan-evidence-in-a-compliance-package)

---

## 1. Executive Summary

veriscan is a deterministic software artifact verification tool designed for defense-grade and air-gapped environments. It enforces an ordered, auditable verification pipeline over software artifacts before they are staged, deployed, or installed. Every decision is backed by structured, machine-readable evidence records.

The following table summarizes veriscan's top-level alignment with major compliance frameworks:

| Framework | Relevant Control Families | veriscan Alignment |
|-----------|--------------------------|-------------------|
| NIST SP 800-53 Rev 5 | CM (Configuration Management) | Supports CM-3, CM-4, CM-7, CM-14 |
| NIST SP 800-53 Rev 5 | SI (System and Information Integrity) | Supports SI-2, SI-3, SI-7, SI-10 |
| NIST SP 800-53 Rev 5 | SA (System and Services Acquisition) | Supports SA-8, SA-9, SA-10, SA-15 |
| NIST SP 800-53 Rev 5 | AU (Audit and Accountability) | Supports AU-2, AU-3, AU-9, AU-12 |
| NIST SP 800-161 Rev 1 | SCRM Controls | Supports C-SCRM throughout supply chain |

veriscan contributes directly to the following security outcomes:

- **Integrity verification** of software artifacts before deployment using cryptographic hashing (SHA-256, SHA-512) and PGP signature verification.
- **Malware screening** via ClamAV integration with bounded, isolated subprocess execution.
- **Threat intelligence correlation** via hash-only VirusTotal lookups (no artifact upload).
- **Tamper detection** through inter-stage artifact hash verification, detecting mutation of artifacts between pipeline stages.
- **Auditable evidence** via structured JSON reports with deterministic evidence item identifiers, supporting chain-of-custody documentation.
- **Air-gapped operation** through offline verification bundles with cryptographically-signed manifests.
- **Policy-driven gating** via a declarative, auditable decision matrix that produces typed verdicts consumable by automated CI/CD pipelines.

---

## 2. NIST SP 800-53 Rev 5 Control Mapping

The following subsections describe how veriscan's design and outputs align with specific controls from NIST SP 800-53 Revision 5. References use the standard control identifier format (Family-Number Enhancement).

### 2.1 Configuration Management (CM) Family

#### CM-3: Configuration Change Control

**Control excerpt (paraphrased):** Analyze the security impact of changes prior to implementation; test, validate, and document changes.

**veriscan alignment:**

The `inspect` stage performs static analysis of every artifact, recording:
- File type (via magic bytes and extension)
- Shannon entropy (detecting packed/encrypted/obfuscated content)
- Extracted string indicators (URLs, PowerShell keywords, shell patterns, base64 blobs)
- Whether the artifact is an executable or script

The `hash` stage computes SHA-256 and SHA-512 and verifies against expected checksums supplied in the policy or adjacent checksum files. A mismatch between the expected and actual hash is a hard `FAILED` result, ensuring that a changed artifact cannot silently pass verification.

The JSON report produced by each run includes the policy digest (SHA-256 of the policy's canonical JSON serialization), making it possible to correlate a specific artifact approval with the exact policy configuration in effect at the time.

**Supporting evidence fields:** `hashes.sha256`, `hashes.sha512`, `hashes.sha256_verified`, `inspection.file_type`, `inspection.entropy`, `policy.digest`

---

#### CM-4: Impact Analysis

**Control excerpt (paraphrased):** Analyze changes to the system to determine potential security impacts before the change is implemented.

**veriscan alignment:**

The static inspection stage provides observable, measurable indicators about an artifact before it is deployed:
- Presence of known-dangerous string patterns (PowerShell invocation, shell command injection patterns, suspicious URLs).
- Shannon entropy above the configured threshold (`max_entropy_threshold`) flags potentially packed or encrypted artifacts for additional review.
- File type classification identifies executables, scripts, and package formats, enabling type-based policy enforcement.

The reputation stage cross-references the artifact's SHA-256 hash against VirusTotal's multi-engine analysis database, providing external threat intelligence as one input to the impact assessment.

**Supporting evidence fields:** `inspection.indicators`, `inspection.entropy_flagged`, `reputation.engines_detected`, `reputation.engines_total`

---

#### CM-7: Least Functionality

**Control excerpt (paraphrased):** Configure the system to provide only essential capabilities; prohibit or restrict the use of functions, ports, protocols, software, and services not required.

**veriscan alignment:**

The `deny_file_types` and `executable_handling` policy controls enforce content-based restrictions:
- `deny_file_types` rejects artifacts whose file type matches a blocklist (e.g., blocking PE executables in a policy that only expects archive files).
- `executable_handling: deny_all` rejects all executables unconditionally.
- `executable_handling: block_unsigned` rejects executables without a verified PGP signature.
- `url_patterns_denylist` rejects artifact download URLs matching disallowed patterns (e.g., rejecting HTTP in favor of HTTPS).

**Supporting policy fields:** `deny_file_types`, `executable_handling`, `url_patterns_denylist`

---

#### CM-14: Signed Components

**Control excerpt (paraphrased):** Prevent the installation of software without verification that the component has been digitally signed using a certificate recognized and approved by the organization.

**veriscan alignment:**

The `signature` stage performs PGP detached signature verification using the `sequoia-openpgp` library with a pure-Rust cryptographic backend. Key features:
- Supports armored (`.asc`) and binary (`.sig`) signature formats.
- Verifies signatures against trusted public keys from a configurable directory.
- Enforces signer fingerprint pinning when `allow_signers` is non-empty — a valid signature from an unknown signer produces `SignerNotAllowed` (FAILED).
- When `require_signature: true`, a missing signature is a hard `FAILED`.

The `allow_signers` field in the policy stores the exact fingerprints (40-hex PGP v4 or 64-hex PGP v5) of approved signing keys. The policy validator rejects fingerprints that do not match these formats.

**Supporting policy fields:** `require_signature`, `allow_signers`, `executable_handling`
**Supporting evidence fields:** `signature.status`, `signature.fingerprint`, `signature.signer_uid`

---

### 2.2 System and Information Integrity (SI) Family

#### SI-2: Flaw Remediation

**Control excerpt (paraphrased):** Identify, report, and correct information system flaws; test software updates before installation.

**veriscan alignment:**

The malware scan stage integrates ClamAV for signature-based detection of known malware and vulnerability exploits in artifact content. Before a software update (artifact) is staged for installation:
- ClamAV scans the artifact bytes.
- Detection names are recorded in the evidence and report.
- A positive detection results in an immediate `FAILED` verdict, blocking installation.

The reputation stage additionally checks the artifact's SHA-256 against VirusTotal. VirusTotal aggregates results from 70+ antivirus engines, increasing the probability that known-flawed or compromised artifacts are identified before deployment.

**Supporting evidence fields:** `malware_scan.status`, `malware_scan.engine`, `malware_scan.detections`, `reputation.status`, `reputation.engines_detected`

---

#### SI-3: Malware Protection

**Control excerpt (paraphrased):** Implement malicious code protection mechanisms at information system entry points and exit points; update mechanisms when new releases are available.

**veriscan alignment:**

The malware stage implements a defense-in-depth layer at artifact intake:
- ClamAV is invoked via a hardened subprocess wrapper with a cleared environment (no secret leakage), absolute binary path requirement (no PATH hijacking), bounded output capture, and a configurable hard timeout.
- The artifact is never executed; only its bytes are passed to `clamscan` as a file path argument.
- The scan engine version is recorded in the evidence item (`tool_versions.clamscan`).
- The `malware_failure_is_fatal` policy flag controls whether an unavailable scanner produces `UNVERIFIED` or `FAILED`.

**Supporting policy fields:** `malware_tool_path`, `malware_scan_required`, `malware_failure_is_fatal`, `subprocess_timeout_seconds`
**Supporting evidence fields:** `malware_scan.status`, `malware_scan.engine_version`

---

#### SI-7: Software, Firmware, and Information Integrity

**Control excerpt (paraphrased):** Employ integrity verification tools to detect unauthorized changes to software, firmware, and information.

**veriscan alignment:**

This control is the primary focus of veriscan. The tool implements multiple layers of integrity verification:

1. **Cryptographic hashing:** SHA-256 and SHA-512 computed over the complete artifact byte stream. Expected values supplied via CLI argument or adjacent checksum files are verified; mismatch is `ERR_HASH_MISMATCH` (FAILED).
2. **PGP signature verification:** Detached signature verification using trusted public keys. Signer fingerprint pinning provides additional assurance.
3. **Inter-stage mutation detection:** The artifact's SHA-256 is re-verified after each pipeline stage. Detection of mutation between stages produces `ERR_ARTIFACT_MUTATED` (FAILED), addressing TOCTOU attacks.
4. **Bundle manifest integrity:** For offline bundles, the manifest's PGP signature is verified before any manifest content is trusted, and every file's hash is verified against the manifest.

**Supporting evidence fields:** `hashes.*`, `signature.*`, all `deterministic_id` fields in the evidence chain

---

#### SI-10: Information Input Validation

**Control excerpt (paraphrased):** Check the validity of information inputs.

**veriscan alignment:**

veriscan validates all user-supplied inputs before use:
- Policy files are parsed with `serde_yaml` and validated by `Policy::validate()`, which checks field ranges, fingerprint format, and required fields.
- `allow_signers` entries are validated to be valid hex fingerprints of the correct length.
- `max_entropy_threshold` is validated to be in [0.0, 8.0].
- Paths from bundle manifests are checked for traversal sequences before any file operations.
- Subprocess binary paths must be absolute (preventing PATH manipulation).
- URL patterns are matched before any network request is initiated.

Invalid policy files produce `ERR_POLICY_INVALID` (exit code 99 — tool error) before any verification begins.

---

### 2.3 System and Services Acquisition (SA) Family

#### SA-8: Security Engineering Principles

**Control excerpt (paraphrased):** Apply security engineering principles in the specification, design, development, implementation, and modification of the system.

**veriscan alignment:**

The following engineering principles are evident in the veriscan design:

| Principle | Implementation |
|-----------|---------------|
| Fail-closed | All unexpected conditions produce UNVERIFIED or FAILED; no silent pass |
| Least privilege | Subprocesses run with a cleared environment; no root required |
| Defense in depth | Seven independent pipeline stages; each stage verifiable independently |
| Separation of concerns | Each stage is an independent module with a typed result |
| Auditability | Every decision is recorded in the decision trace and evidence chain |
| No execution of untrusted inputs | Artifact bytes are never executed, only read |
| Typed error handling | `VeriError` enum prevents generic error handling from swallowing failures |

---

#### SA-9: External System Services

**Control excerpt (paraphrased):** Require external service providers to implement security controls; monitor provider compliance.

**veriscan alignment:**

veriscan's only external service dependency is the VirusTotal API (reputation stage). Controls applied to this dependency:
- Only the artifact's SHA-256 hash is transmitted — never the artifact bytes themselves.
- The API key is read from an environment variable, never stored in policy files or on disk.
- API calls use TLS encryption.
- Results are cached locally with a configurable TTL (`reputation_cache_ttl_seconds`).
- Unavailability of the VirusTotal service degrades gracefully to `UNVERIFIED` or `FAILED` depending on `reputation_failure_is_fatal`.
- The air-gapped policy (`airgapped.yaml`) sets `allow_network: false`, disabling all external calls entirely.

**Supporting policy fields:** `vt_api_key_env`, `reputation_required`, `reputation_failure_is_fatal`, `allow_network`, `network_timeout_seconds`

---

#### SA-10: Developer Configuration Management

**Control excerpt (paraphrased):** Require developers to perform configuration management including tracking approved changes.

**veriscan alignment:**

The policy digest feature enables configuration management of verification policies:
- Each policy document's SHA-256 digest is included in every report.
- Changes to policy configuration are detectable by comparing digests across runs.
- The policy `version` field provides a human-readable change identifier.
- Policy files can be managed in version control and their digests validated in audit workflows.

**Supporting report fields:** `policy.name`, `policy.version`, `policy.digest`

---

#### SA-15: Development Process, Standards, and Tools

**Control excerpt (paraphrased):** Require development process to follow security engineering standards.

**veriscan alignment:**

- veriscan is written in Rust, a memory-safe language by default.
- The release profile enables LTO, single codegen unit, and symbol stripping.
- No `unsafe` blocks in security-critical code paths.
- Dependencies are pinned and audited via `cargo audit`.
- The test suite includes pipeline invariant tests (`tests/pipeline_invariants.rs`), policy decision tests (`tests/policy_decisions.rs`), and offline bundle tests (`tests/offline_bundle.rs`).

---

### 2.4 Audit and Accountability (AU) Family

#### AU-2: Event Logging

**Control excerpt (paraphrased):** Identify the types of events that the system is capable of logging in support of the audit function.

**veriscan alignment:**

veriscan emits structured JSON logs via the `tracing` subsystem for every significant event:
- Pipeline start and stage transitions.
- Verification outcomes (VERIFIED, UNVERIFIED, FAILED) with reasons.
- External tool invocations and their exit codes.
- Network requests (URL, status code — not API keys).
- Error conditions with stable error codes (e.g., `ERR_HASH_MISMATCH`).

The `--audit-log` CLI flag directs structured log output to a file separate from the main report.

---

#### AU-3: Content of Audit Records

**Control excerpt (paraphrased):** Ensure audit records contain information to establish: what type of event occurred, when, where, source, outcome, and identity of associated subjects.

**veriscan alignment:**

Every JSON report contains:

| Audit element | veriscan field |
|--------------|---------------|
| What type of event | `verdict.status` and per-stage status fields |
| When | `timestamp` (ISO 8601 UTC), `elapsed_secs` |
| Where (source) | `artifact.source`, `artifact.filename` |
| Outcome | `verdict.status`, `verdict.exit_code`, `verdict.reason` |
| Evidence of outcome | `decision_trace[]`, `evidence[]` |
| Who (policy) | `policy.name`, `policy.version`, `policy.digest` |
| Run correlation | `run_id` (UUID v4) |

Each evidence item also carries:
- `timestamp` — when the evidence was collected.
- `stage_name` — which pipeline stage produced it.
- `inputs` — what was analyzed.
- `outputs` — what was observed.
- `tool_versions` — which external tool versions were involved.
- `deterministic_id` — SHA-256 of the canonical evidence record, enabling tamper detection.

---

#### AU-9: Protection of Audit Information

**Control excerpt (paraphrased):** Protect audit information and tools from unauthorized access, modification, and deletion.

**veriscan alignment:**

The `deterministic_id` field on each evidence item is the SHA-256 of the canonical serialization of that item's content (stage name, inputs, outputs, tool versions). Any modification of an evidence record in the report will cause its `deterministic_id` to no longer match. While veriscan does not sign its output reports, the evidence chain provides a tamper-evident structure. Operators requiring tamper-proof audit logs should:
1. Pipe the JSON report through a signing step (e.g., `gpg --detach-sign report.json`).
2. Write reports to append-only or WORM storage.
3. Compute and store a hash of the JSON report alongside the report.

---

#### AU-12: Audit Record Generation

**Control excerpt (paraphrased):** Allow designated organizational personnel to select which auditable events are to be logged.

**veriscan alignment:**

The policy decision matrix allows operators to configure which conditions generate decision trace entries and at what severity level (VERIFIED, UNVERIFIED, FAILED). Every rule evaluated — whether it matches or not — is recorded in the `decision_trace` array, providing a complete audit record of the policy evaluation logic for every run.

---

## 3. NIST SP 800-161 Rev 1 SCRM Mapping

NIST SP 800-161 Revision 1 (Cybersecurity Supply Chain Risk Management Practices for Systems and Organizations) addresses the unique challenges of managing cybersecurity risks throughout the supply chain. The following maps veriscan capabilities to C-SCRM relevant controls.

### 3.1 Supply Chain Risk Management Strategy

**Relevant control areas:** PM-30 (Supply Chain Risk Management Strategy), SR-1 (Policy and Procedures)

**veriscan alignment:**

veriscan provides operational tooling to execute a supply chain risk management strategy. It does not define the strategy itself — that is an organizational function. However:
- Policy files provide a machine-readable, auditable definition of the acceptance criteria for each artifact type and use case.
- Four reference policies are provided: `default.yaml`, `contractor_strict.yaml`, `airgapped.yaml`, `ci_gate.yaml`.
- Policy digests allow an organization to version-control and audit changes to their acceptance criteria.

---

### 3.2 Provenance and Authenticity

**Relevant control areas:** SR-4 (Provenance), SR-6 (Supplier Assessments and Reviews)

**veriscan alignment:**

Provenance verification in veriscan:
- **PGP signature verification** establishes that an artifact was signed by a known key. Combined with signer fingerprint pinning (`allow_signers`), this provides cryptographic provenance: the artifact can be attributed to the specific signing entity whose key is in the allow list.
- **Checksum verification** against supplier-published checksums provides a second provenance signal.
- **VirusTotal reputation** provides a crowd-sourced third-party assessment of the artifact's hash.
- The `signature.signer_uid` field in the report records the PGP User ID of the verified signer, supporting supplier attribution in audit records.

---

### 3.3 Component Integrity

**Relevant control areas:** SR-4 (Provenance), SR-9 (Tamper Protection), SR-10 (Inspection of Systems)

**veriscan alignment:**

- SHA-256 and SHA-512 hashing provide cryptographic evidence that an artifact has not been modified since the hashes were computed.
- Inter-stage mutation detection (`ERR_ARTIFACT_MUTATED`) provides assurance that no process in the verification environment tampers with the artifact during verification.
- The offline bundle format (`bundle.manifest.json` + `bundle.manifest.sig`) provides tamper-evident transport for all artifacts and their verification metadata.

---

### 3.4 Criticality Analysis

**Relevant control areas:** RA-9 (Criticality Analysis), SR-2 (Supply Chain Risk Assessment)

**veriscan alignment:**

The policy engine supports risk-tiered configurations:
- `contractor_strict.yaml` — maximum requirements; all checks required; any failure is fatal.
- `default.yaml` — balanced requirements suitable for general use.
- `ci_gate.yaml` — automated gating with sensible defaults for CI environments.
- `airgapped.yaml` — network-isolated operation for the highest-sensitivity environments.

Different artifact types or criticality levels can be processed under different policies, and the policy name and digest in every report make it auditable which criticality tier was applied.

---

### 3.5 Software Integrity Verification

**Relevant control areas:** SR-11 (Component Authenticity), SA-10 (Developer Configuration Management)

**veriscan alignment:**

This is the core purpose of veriscan. Every artifact that passes through the pipeline generates:
- A signed evidence chain with deterministic identifiers.
- A JSON report that serves as a verifiable artifact approval record.
- A Markdown report that serves as a human-readable summary for review boards.
- A decision trace that records every policy rule evaluated and its outcome.

These outputs are designed to serve as the primary record of software intake verification in a C-SCRM program.

---

### 3.6 Air-Gapped and Isolated Operations

**Relevant control areas:** SC-7 (Boundary Protection), SR-4 (Provenance) in isolated environments

**veriscan alignment:**

The offline bundle feature addresses supply chain verification in environments where network connectivity is prohibited:
- A bundle is assembled in a connected environment, cryptographically sealed, and transferred to the air-gapped environment.
- In the air-gapped environment, `veriscan verify --offline <bundle>` verifies the bundle manifest signature, all file hashes, the artifact signature, and runs the full pipeline with `allow_network: false`.
- No network calls are made in offline mode. Reputation checks gracefully degrade to `UNVERIFIED`.
- The `malware_failure_is_fatal: true` option in the airgapped policy ensures that if a local ClamAV installation is required and unavailable, the verification fails rather than silently skipping malware checking.

---

## 4. Evidence Produced by veriscan

Every verification run produces the following artifacts that can be included in a compliance package or audit record:

### 4.1 JSON Verification Report (machine-readable)

A structured JSON document with schema version `1.0`. Fields include:

| Field | Description | Compliance use |
|-------|-------------|---------------|
| `run_id` | UUID v4 unique to this run | Audit trail correlation |
| `timestamp` | ISO 8601 UTC run timestamp | Event log timestamping |
| `artifact.source` | URL or file path of artifact | Artifact provenance |
| `artifact.filename` | Canonical filename | Artifact identification |
| `artifact.size_bytes` | File size | Integrity baseline |
| `verdict.status` | VERIFIED / UNVERIFIED / FAILED | Pass/fail gating |
| `verdict.exit_code` | 0 / 10 / 20 | CI/CD pipeline integration |
| `hashes.sha256` | Hex SHA-256 | Integrity evidence |
| `hashes.sha512` | Hex SHA-512 | Integrity evidence |
| `hashes.sha256_verified` | Boolean — matched expected? | Checksum verification |
| `signature.status` | verified / missing / invalid | Authenticity evidence |
| `signature.fingerprint` | PGP key fingerprint | Signer attribution |
| `signature.signer_uid` | PGP User ID | Supplier attribution |
| `malware_scan.status` | clean / detected / tool_missing | Malware screening evidence |
| `malware_scan.engine_version` | ClamAV version used | Tool provenance |
| `reputation.status` | clean / malicious / unknown | Threat intelligence |
| `reputation.engines_detected` | Count of detections | Threat severity |
| `inspection.entropy` | Shannon entropy (0–8) | Obfuscation indicator |
| `inspection.indicators` | String-based indicators | Static analysis findings |
| `policy.name` | Policy name applied | Policy attribution |
| `policy.digest` | SHA-256 of policy | Policy integrity |
| `decision_trace[]` | All rules evaluated and outcomes | Full audit trail |
| `evidence[]` | Structured evidence items | Chain of custody |

### 4.2 Evidence Items (per-stage, within JSON report)

Each evidence item carries:
- `timestamp` — ISO 8601 UTC.
- `stage_name` — one of: `acquire`, `hash`, `signature`, `malware`, `inspect`, `reputation`, `policy`.
- `inputs` — named inputs to the stage.
- `outputs` — named, typed outputs (hashes, scan results, parsed fields).
- `tool_versions` — versions of external tools used.
- `deterministic_id` — SHA-256 of the canonical serialization of the evidence item.

### 4.3 Markdown Report (human-readable)

A formatted Markdown document suitable for inclusion in change records, deployment approvals, and audit packages. Contains the same data as the JSON report in tabular form.

### 4.4 Structured Audit Logs

When `--audit-log <path>` is specified, structured JSON log events are written to the specified file. These include every stage transition, external tool invocation, and error event with associated metadata.

---

## 5. Limitations — What veriscan Does Not Claim

This section is required reading for compliance officers and auditors.

| Limitation | Explanation |
|------------|-------------|
| **Not a certification** | veriscan holds no FedRAMP, FIPS 140-2/3, Common Criteria, or other third-party certification. |
| **Not a complete SCRM program** | veriscan is one operational tool. A complete C-SCRM program requires organizational policies, supplier agreements, incident response procedures, and ongoing risk assessment processes. |
| **Does not guarantee safety** | A `VERIFIED` verdict means the artifact passed all configured checks at the time of verification. It does not guarantee the artifact is free of all vulnerabilities, logic bombs, or undiscovered malware. |
| **Does not validate business logic** | veriscan has no knowledge of what an artifact is supposed to do. It cannot detect intentional backdoors or logic bombs in otherwise correctly-signed, malware-database-clean code. |
| **No SBOM enforcement (current version)** | The `require_sbom` policy flag produces `UNVERIFIED` rather than `FAILED`. Full SBOM enforcement is planned for a future phase. |
| **Reputation data is not real-time** | VirusTotal results represent the state of analysis at the time of the query, subject to the local cache TTL. |
| **ClamAV signatures must be maintained** | veriscan does not update ClamAV signature databases. The malware scan is only as current as the installed ClamAV database. |
| **PGP trust is only as strong as key management** | Compromised signing keys, insider threats with key access, and key revocation delays are outside veriscan's scope. |
| **Control satisfaction requires operator procedures** | The NIST control mappings in Section 2 indicate alignment, not automatic satisfaction. Auditors must assess the complete implementation context. |

---

## 6. Using veriscan Evidence in a Compliance Package

### 6.1 Artifact Approval Records

For each artifact approved for deployment in a regulated environment:

1. Run `veriscan verify` with the appropriate policy for the deployment tier.
2. Save the JSON report with a filename that includes the artifact hash and run ID, e.g., `report-<sha256[:8]>-<run_id>.json`.
3. Optionally sign the JSON report with a GPG key controlled by the approving individual or automated system.
4. Store the signed report in the artifact management system or change management tool alongside the artifact.

### 6.2 Policy Documentation

For each policy applied:

1. Maintain policy files in version control with a documented review and approval process.
2. The policy digest in each report provides a cryptographic link between the approval record and the exact policy text in effect at the time of approval.
3. Changes to policy files should follow the organization's change management process, with before/after digest comparison documented.

### 6.3 Audit Trail Generation

For audit periods:

1. Collect all JSON reports from the audit period.
2. The `run_id`, `timestamp`, `policy.digest`, and `verdict.status` fields support automated audit queries.
3. The `decision_trace` array in each report provides a human-readable and machine-readable explanation of every policy rule evaluation.
4. The `evidence[].deterministic_id` chain allows auditors to verify that evidence records have not been modified after the fact.

### 6.4 Example Audit Query (jq)

```bash
# List all FAILED verdicts in a directory of JSON reports
for f in reports/*.json; do
  jq -r '"\(.timestamp) \(.artifact.filename) \(.verdict.status) \(.verdict.reason // "")"' "$f"
done | grep FAILED

# Verify that all reports used the expected policy digest
EXPECTED_DIGEST="<sha256-of-approved-policy>"
for f in reports/*.json; do
  ACTUAL=$(jq -r '.policy.digest' "$f")
  if [ "$ACTUAL" != "$EXPECTED_DIGEST" ]; then
    echo "Policy mismatch in $f: $ACTUAL"
  fi
done
```

### 6.5 Integration with SIEM / SOAR

The JSON report schema (version `1.0`) is stable and additive — new fields may be added in future versions but existing fields will not be removed or renamed. The schema is printable via:

```bash
veriscan report-schema
```

JSON reports can be ingested by SIEM platforms (Splunk, Elastic, etc.) by indexing the `reports/` directory or piping reports to a log aggregator. The `run_id` field serves as the event correlation identifier.

---

*This compliance document reflects the design of veriscan as of the stated version. Organizations should conduct their own assessment of how veriscan integrates into their specific control environment before making compliance claims.*
