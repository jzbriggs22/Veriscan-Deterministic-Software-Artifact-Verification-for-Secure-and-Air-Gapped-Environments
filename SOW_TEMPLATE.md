# Statement of Work
## Veriscan Software Artifact Verification Capability

**Document Version:** 1.0
**Prepared By:** [Prime Contractor Organization — TBD]
**Prepared For:** [Customer Organization — TBD]
**Contract/Task Order Number:** [TBD]
**Period of Performance:** [TBD]
**Classification:** [TBD]

---

## Section 1: Objectives

### 1.1 Purpose

The purpose of this Statement of Work (SOW) is to define the requirements, tasks, deliverables, and acceptance criteria for the development, documentation, testing, and delivery of the **Veriscan Software Artifact Verification Capability** — a defense-grade, deterministic CLI tool for verifying the integrity, authenticity, and risk posture of software artifacts in secure and air-gapped environments.

### 1.2 Background

[Customer organization — TBD] requires a software artifact verification capability that enforces mandatory verification controls before any software artifact enters a controlled environment. Existing tools either require network connectivity, rely on opaque verification logic, or do not produce audit-grade evidence records suitable for compliance reporting. Veriscan addresses these gaps through a deterministic, ordered verification pipeline backed by a structured evidence model.

### 1.3 Objectives

The contractor shall deliver a capability that:

1. Verifies software artifacts through a mandatory, ordered, non-bypassable pipeline: Acquire → Hash → Signature → Malware → Inspect → Reputation → Policy.
2. Operates in fully offline and air-gapped environments using pre-packaged verification bundles.
3. Integrates with CI/CD pipelines as an automated gate using deterministic exit codes.
4. Produces machine-readable (JSON) and human-readable (Markdown) reports containing audit-grade evidence for every verification decision.
5. Enforces declarative YAML policies without hidden defaults or silent bypass paths.
6. Aligns with NIST SP 800-53 Rev 5 and NIST SP 800-161 Rev 1 supply chain risk management controls.

---

## Section 2: Scope of Work / Tasks

### 2.1 Phase I — Core CLI and Documentation (Current Scope)

#### Task 2.1.1: Core CLI Implementation

The contractor shall deliver a compiled `veriscan` CLI binary implementing the following subcommands:

- `verify` — Run the full verification pipeline on a local file path or HTTPS URL.
- `verify --offline <BUNDLE_DIR>` — Run verification against an offline verification bundle.
- `bundle create` — Create an offline verification bundle from an artifact and signing key.
- `policy-validate` — Validate a YAML policy file and report its SHA-256 digest.
- `report-schema` — Print the stable JSON report schema (v1.0).

The pipeline shall enforce the following stage order without exception:

```
Acquire → Hash → Signature → Malware → Inspect → Reputation → Policy
```

No CLI argument, environment variable, or policy setting shall be capable of reordering, skipping, or bypassing any stage.

#### Task 2.1.2: Verification Pipeline Stages

The contractor shall implement all seven pipeline stages:

| Stage | Capability |
|---|---|
| Acquire | Local file and HTTPS URL acquisition; URL denylist enforcement |
| Hash | SHA-256 and SHA-512 computation; expected checksum verification; adjacent checksum file detection |
| Signature | PGP detached signature verification (pure-Rust via sequoia-openpgp); signer fingerprint pinning |
| Malware | ClamAV subprocess integration; bounded output; timeout enforcement; clear subprocess environment |
| Inspect | Magic-byte file type detection; Shannon entropy computation; string extraction; indicator scanning |
| Reputation | VirusTotal v3 hash-only lookup; local result cache with configurable TTL; API key from environment variable only |
| Policy | YAML decision matrix evaluation; typed verdict (VERIFIED / UNVERIFIED / FAILED); full decision trace |

#### Task 2.1.3: Offline Bundle Support

The contractor shall implement the offline verification bundle format including:

- Bundle creation (`bundle create`) producing: artifact, SHA-256/SHA-512 checksums, PGP signature, trusted public keys, signed manifest.
- Bundle verification that validates manifest PGP signature before reading any other bundle content.
- Per-file hash verification against the signed manifest.
- Path traversal prevention in bundle path resolution.

#### Task 2.1.4: Policy Engine

The contractor shall deliver four reference policy configurations:

| Policy | Description |
|---|---|
| `default.yaml` | General verification with balanced requirements |
| `contractor_strict.yaml` | High-assurance defense environment policy |
| `airgapped.yaml` | Air-gapped, no-network policy |
| `ci_gate.yaml` | Automated CI/CD pipeline gating policy |

#### Task 2.1.5: Reporting

The contractor shall produce for every verification run:

- A JSON report conforming to the stable v1.0 schema.
- A Markdown report suitable for analyst and auditor review.
- Both reports generated from a single shared data structure to prevent divergence.

#### Task 2.1.6: Evidence Model

The contractor shall implement the structured evidence model such that:

- Every pipeline stage produces one or more `EvidenceItem` records.
- Each `EvidenceItem` carries a deterministic SHA-256 identifier computed from its canonical representation.
- Evidence items are assembled into the JSON report in pipeline stage order.
- Evidence records include: timestamp, stage name, named inputs, named typed outputs, and external tool version strings.

#### Task 2.1.7: Documentation

The contractor shall deliver the following documentation:

| Document | Location |
|---|---|
| README | `README.md` |
| Capability Statement | `CAPABILITY_STATEMENT.md` |
| Statement of Work Template | `SOW_TEMPLATE.md` |
| Architecture Document | `docs/architecture.md` |
| Threat Model | `docs/threat_model.md` |
| Evidence Model | `docs/evidence_model.md` |
| Demo Guide | `docs/demo_guide.md` |
| NIST SP 800-53 Rev 5 Control Mapping | `docs/controls/nist_800_53_rev5.md` |
| NIST SP 800-161 Rev 1 SCRM Mapping | `docs/controls/nist_800_161.md` |
| Compliance Matrix (CSV) | `docs/controls/compliance_matrix.csv` |

#### Task 2.1.8: Demo Environment

The contractor shall deliver:

- Online demo scripts covering: VERIFIED artifact, FAILED tampered artifact, UNVERIFIED unsigned artifact, FAILED malware simulation.
- Offline demo scripts covering: VERIFIED bundle, FAILED tampered bundle, FAILED tampered manifest, FAILED missing signature.
- A Docker-based demo environment (`demo/docker/`) packaging ClamAV, GnuPG, and veriscan.
- A `make_bundle.sh` script for generating demo artifacts and signing keys.

### 2.2 Phase II — SBOM, Reproducible Builds, and Extended Integrations (Future Scope)

The following capabilities are planned for Phase II and are not included in the current SOW. Requirements will be defined in a follow-on task order.

#### Task 2.2.1: Software Bill of Materials (SBOM) Verification

- CycloneDX and SPDX SBOM parsing and verification.
- SBOM attachment to offline bundles.
- Policy enforcement for SBOM presence and component allowlisting.

#### Task 2.2.2: Reproducible Build Verification

- Integration with reproducible build toolchains (Bazel, Nix, Guix).
- Hash comparison against published reproducible build outputs.
- Build attestation verification (SLSA provenance).

#### Task 2.2.3: Extended Integrations

- Native GitHub Actions action.
- Native GitLab CI component.
- SIEM integration documentation (structured JSON log format).
- Splunk and Elastic SIEM dashboard examples.

---

## Section 3: Deliverables

### 3.1 Phase I Deliverables

| ID | Deliverable | Format | Delivery Method |
|---|---|---|---|
| D-01 | `veriscan` compiled binary (Linux x86-64) | ELF binary (stripped, LTO) | Git release tag |
| D-02 | `veriscan` compiled binary (macOS arm64) | Mach-O binary | Git release tag |
| D-03 | Source code repository | Rust / TOML / YAML | Git repository |
| D-04 | Policy files (4 profiles) | YAML | `policies/` directory |
| D-05 | JSON report schema | JSON / CLI output | `veriscan report-schema` |
| D-06 | README | Markdown | `README.md` |
| D-07 | Capability Statement | Markdown | `CAPABILITY_STATEMENT.md` |
| D-08 | SOW Template | Markdown | `SOW_TEMPLATE.md` |
| D-09 | Architecture document | Markdown | `docs/architecture.md` |
| D-10 | Threat model | Markdown | `docs/threat_model.md` |
| D-11 | Evidence model | Markdown | `docs/evidence_model.md` |
| D-12 | Demo guide | Markdown | `docs/demo_guide.md` |
| D-13 | NIST 800-53 control mapping | Markdown | `docs/controls/nist_800_53_rev5.md` |
| D-14 | NIST 800-161 SCRM mapping | Markdown | `docs/controls/nist_800_161.md` |
| D-15 | Compliance matrix | CSV | `docs/controls/compliance_matrix.csv` |
| D-16 | Online demo scripts | Shell | `demo/scripts/` |
| D-17 | Offline demo scripts | Shell | `demo/scripts/` |
| D-18 | Docker demo environment | Dockerfile / docker-compose | `demo/docker/` |
| D-19 | Integration test suite | Rust | `tests/` |

---

## Section 4: Milestones and Schedule

| Milestone | Description | Target Date |
|---|---|---|
| M-01 | Project kick-off and requirements confirmation | [TBD] |
| M-02 | Core pipeline implementation complete (Tasks 2.1.1–2.1.4) | [TBD] |
| M-03 | Reporting and evidence model complete (Tasks 2.1.5–2.1.6) | [TBD] |
| M-04 | Documentation package complete (Task 2.1.7) | [TBD] |
| M-05 | Demo environment and scripts complete (Task 2.1.8) | [TBD] |
| M-06 | Integration test suite complete | [TBD] |
| M-07 | Government review period | [TBD] |
| M-08 | Final delivery and acceptance | [TBD] |
| M-09 | Phase II kick-off (follow-on task order) | [TBD] |

---

## Section 5: Acceptance Criteria

### 5.1 Functional Acceptance

The Government will accept Phase I deliverables when all of the following criteria are met:

**5.1.1 Pipeline Integrity**
- The verification pipeline executes in the fixed order: Acquire → Hash → Signature → Malware → Inspect → Reputation → Policy.
- No CLI argument or policy setting causes any stage to be skipped or reordered.
- Artifact hash is verified before and after each stage; any in-pipeline mutation produces exit code 20 (FAILED).

**5.1.2 Exit Code Compliance**
- Exit code 0 is produced if and only if the policy evaluates to VERIFIED.
- Exit code 10 is produced when verification is UNVERIFIED (incomplete checks; no definitive failure).
- Exit code 20 is produced when verification is FAILED (definitive failure: hash mismatch, malware, invalid signature).
- Exit code 99 is produced for tool errors (policy invalid, I/O failure).

**5.1.3 Evidence Completeness**
- Every pipeline run produces at least one `EvidenceItem` per stage executed.
- Each `EvidenceItem` carries a valid SHA-256 `deterministic_id` computed from its canonical representation.
- The JSON report includes the complete evidence array.

**5.1.4 Offline Bundle Verification**
- A bundle with a valid manifest signature and correct file hashes produces exit code 0 or 10.
- A bundle with a tampered artifact file produces exit code 20.
- A bundle with a tampered manifest produces exit code 20.
- A bundle with a missing manifest signature produces exit code 20 (or 99 if treated as an error).

**5.1.5 Policy Enforcement**
- `contractor_strict.yaml`: artifacts without a valid PGP signature produce exit code 20.
- `airgapped.yaml`: any network call is rejected with exit code 99.
- `ci_gate.yaml`: unsigned or hash-unverified artifacts produce exit code 20.

**5.1.6 Security Requirements**
- No API key, secret, or credential appears in any log output, report file, or evidence record.
- ClamAV subprocess is invoked via absolute path only; subprocess environment is cleared.
- Bundle path traversal attempts are rejected with a descriptive error.

### 5.2 Documentation Acceptance

All documentation deliverables (D-06 through D-15) shall:
- Be written in valid Markdown.
- Accurately reflect the implemented behavior as verified by the acceptance tests.
- Include no placeholder `[TBD]` fields in technical content sections (customer-specific fields excepted).

### 5.3 Test Acceptance

The integration test suite shall pass with no failures when executed via `cargo test` on a clean Linux environment with Rust 1.70+.

---

## Section 6: Assumptions and Constraints

### 6.1 Assumptions

1. The customer organization will provide signing keys, expected checksums, and VirusTotal API keys for production deployments. Demo materials use generated test keys only.
2. ClamAV virus definitions will be maintained by the deploying organization. Veriscan does not manage ClamAV database updates.
3. The VirusTotal API key, if used, will be provided as an environment variable (`VT_API_KEY` by default, configurable per policy). The key will not be stored in policy files or source code.
4. Air-gapped environment deployments will use the offline bundle workflow. Veriscan does not provide a mechanism to update ClamAV definitions in an air-gapped environment; that is the deploying organization's responsibility.
5. The deploying organization is responsible for maintaining the trusted key store (`allow_signers`, `trusted_keys/` directory).

### 6.2 Constraints

1. Veriscan does not execute artifacts at any point. Behavioral analysis is out of scope.
2. Zero-day malware with no ClamAV signatures is not detected by the malware stage. The reputation stage provides a complementary control but also relies on known-bad hash databases.
3. Nation-state implants in legitimately signed upstream releases are not within the detection scope of Veriscan. Defense against such threats requires reproducible build verification (Phase II) and organizational supply chain audits.
4. Veriscan does not manage firewall rules, network access controls, or system hardening. It is a verification tool, not an enforcement broker for network-layer controls.
5. The SBOM verification capability is Phase II only. The `require_sbom: true` policy flag currently produces UNVERIFIED, not FAILED.

---

## Section 7: Government Furnished Information

The following information shall be provided by the Government prior to or during performance:

| GFI Item | Description | Required By Milestone |
|---|---|---|
| GFI-01 | Approved signing key fingerprints for production `allow_signers` lists | M-05 |
| GFI-02 | VirusTotal API key (if reputation checking is required in production) | M-02 |
| GFI-03 | ClamAV database access or pre-populated database for air-gapped deployments | M-05 |
| GFI-04 | Target deployment environment specification (OS, Rust version, CI/CD platform) | M-01 |
| GFI-05 | Sample artifacts for acceptance testing (clean, tampered, unsigned, malware-simulated) | M-06 |
| GFI-06 | Approved URL denylist entries for production policy files | M-05 |
| GFI-07 | Audit log destination specification (file path, SIEM endpoint) | M-04 |

---

## Section 8: Reporting Requirements

### 8.1 Progress Reports

The contractor shall provide written progress reports to the Contracting Officer's Representative (COR) on the following schedule:

| Report | Frequency | Format |
|---|---|---|
| Weekly Status | Weekly | Email / Memorandum |
| Milestone Completion Report | Upon each milestone completion | Formal memorandum |
| Deficiency Report | Within 24 hours of critical issue identification | Email |
| Final Technical Report | Upon final delivery (M-08) | Formal document |

### 8.2 Weekly Status Report Contents

Each weekly status report shall include:

1. Tasks completed during the reporting period.
2. Tasks planned for the next reporting period.
3. Any schedule variances with explanation and corrective action.
4. Any open risks or issues requiring Government action.
5. Deliverable status (not started / in progress / complete / accepted).

### 8.3 Milestone Completion Report Contents

Each milestone completion report shall include:

1. Milestone identifier and description.
2. Deliverables included in the milestone.
3. Summary of testing performed and results.
4. Any deviations from the approved design.
5. Known limitations or open items.

### 8.4 Machine-Readable Verification Reports

For any veriscan verification run performed as part of acceptance testing, the contractor shall provide:

- The complete JSON report (`--report-json`).
- The Markdown report (`--report-md`).
- The policy file used (with its SHA-256 digest as printed by `veriscan policy-validate`).

---

*This Statement of Work template is provided for use by prime contractor organizations. Customer-specific fields marked [TBD] must be completed before issuance. Technical content reflects the Veriscan capability as implemented in Phase I.*
