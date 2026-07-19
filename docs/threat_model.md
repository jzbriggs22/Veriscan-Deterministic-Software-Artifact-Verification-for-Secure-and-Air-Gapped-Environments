# Threat Model

## Veriscan Software Artifact Verification

**Version:** 1.0
**Last Updated:** 2025

---

## 1. System Overview

Veriscan is a CLI tool that verifies software artifacts before they enter a controlled environment. It operates as a gate between artifact sources (vendor deliveries, upstream repositories, internal builds) and deployment targets (staging systems, production environments, air-gapped networks). Veriscan does not control the network, enforce filesystem permissions, or manage signing key infrastructure; it is a verification tool that produces auditable evidence of artifact inspection.

### System Components

```
 [Artifact Source]         [Veriscan]                  [Controlled Environment]
 ─────────────────         ──────────                  ───────────────────────
 Vendor HTTPS server ──►   Acquire                     Staging system
 Local filesystem    ──►   Hash verification      ──►  Air-gapped network
 Offline bundle      ──►   PGP sig verification        Production deployment
                           ClamAV scan
                           Static inspection
                           VT reputation lookup
                           Policy evaluation
                           Evidence + report
```

Veriscan has no network-enforcement capability; it cannot block traffic. Its verdicts are advisory inputs to a CI/CD gate or a human operator who decides whether to proceed.

---

## 2. Assets Being Protected

| Asset | Description | Value |
|---|---|---|
| **Controlled deployment environment** | Servers, workstations, or networks into which software artifacts are deployed | Critical — compromise enables code execution |
| **Artifact integrity** | Assurance that deployed software is exactly the artifact the vendor or developer intended | High — corruption or substitution enables backdoors |
| **Artifact authenticity** | Assurance that the artifact was signed by an authorized party | High — unauthorized signing enables impersonation |
| **Signing key material** | Private keys held by authorized signers | Critical — key compromise undermines all signature checks |
| **Verification evidence** | The JSON/Markdown reports produced by veriscan | Medium — tampering with evidence undermines audit validity |
| **Policy configuration** | YAML policy files defining verification requirements | Medium — weakened policy silently bypasses controls |
| **API keys** | VirusTotal API key used for reputation lookup | Low (operational) — exposure enables quota abuse |

---

## 3. Threat Actors

### 3.1 Opportunistic Attacker

**Profile:** Automated scripts, commodity malware distribution, drive-by supply chain attacks targeting widely-used open-source packages.

**Motivation:** Broad compromise; financial gain via ransomware, cryptomining, or data theft.

**Capabilities:** Mass-distributed malware with known signatures; mirror poisoning targeting popular package registries; checksum substitution in HTTP-served downloads; no targeted intelligence about the victim organization.

**Relevance to Veriscan:** Opportunistic attacks are the primary threat class veriscan is designed to detect. ClamAV signature-based detection, VirusTotal reputation checking, and hash/signature verification together provide strong defense against this class.

### 3.2 Nation-State / Advanced Persistent Threat (APT)

**Profile:** Well-resourced, patient attackers with specific target intelligence.

**Motivation:** Espionage, sabotage, intellectual property theft, long-term persistence.

**Capabilities:** Zero-day exploits; ability to compromise signing infrastructure; supply chain implants in legitimate upstream releases (e.g., SolarWinds, XZ Utils); insider recruitment; compromised build systems; ability to evade known-malware signatures.

**Relevance to Veriscan:** Veriscan provides meaningful defense against APT tactics involving artifact substitution and checksum bypass. It does not provide reliable defense against APT actors who have compromised the upstream signing key or the build system used to produce the artifact. Phase II reproducible build verification partially addresses the build system threat.

### 3.3 Insider Threat

**Profile:** Authorized personnel with legitimate access to signing keys, build systems, or the deployment pipeline itself.

**Motivation:** Financial gain, coercion, ideology, personal grievance.

**Capabilities:** Ability to produce legitimately-signed malicious artifacts; ability to modify policy files; ability to suppress or falsify verification reports; ability to weaken policy (e.g., emptying `allow_signers`, setting `require_signature: false`).

**Relevance to Veriscan:** Veriscan provides limited defense against insider threats with access to signing keys, as a legitimately-signed malicious artifact will pass signature verification. Mitigations include: fingerprint pinning (`allow_signers`), VirusTotal reputation checking, ClamAV scanning, static inspection for suspicious indicators, and policy digest binding. Organizational controls (access reviews, separation of duties, audit logs) are the primary defense against insider threats.

### 3.4 Unskilled/Accidental Actor

**Profile:** Developers or operators who introduce unsigned, unverified, or incorrectly packaged artifacts without malicious intent.

**Motivation:** None; errors of omission or process gaps.

**Capabilities:** Ability to bypass policy through misconfiguration if not prevented.

**Relevance to Veriscan:** Policy enforcement (`require_signature`, `require_checksums`, `executable_handling: block_unsigned`) provides strong defense against accidental introduction of unverified software. Fail-closed design prevents silent bypass.

---

## 4. Attack Vectors

### 4.1 Corrupted Download / Bit Flip

**Description:** The artifact is corrupted in transit or on disk due to hardware error, network failure, or storage fault.

**Control:** Hash stage. SHA-256 and SHA-512 are computed and compared against expected values. Any discrepancy causes FAILED (exit 20).

**Residual Risk:** If no expected checksum is provided and `require_checksums: false`, corruption is not detected. Operators must provide expected checksums for this control to be effective.

### 4.2 Man-in-the-Middle (MITM) — HTTP

**Description:** An attacker intercepts an HTTP download and substitutes a malicious artifact.

**Controls:** (1) URL denylist can block `http://` sources. (2) Hash verification detects substitution if expected checksums are provided. (3) Signature verification detects substitution if the attacker cannot forge the signing key.

**Residual Risk:** MITM on HTTPS requires a compromised CA certificate; this is treated as out of scope. MITM on HTTP is partially mitigated by hash verification (if expected checksums are known in advance) and fully mitigated if the URL denylist blocks `http://` sources.

### 4.3 Mirror Tampering

**Description:** A package mirror, CDN, or distribution infrastructure is compromised. The attacker replaces the artifact and updates the checksum files hosted at the same location.

**Controls:** Signature verification. An attacker who tampers with the artifact cannot produce a valid PGP signature from an authorized key (unless they also compromise the signing key). If expected checksums are provided out-of-band (not from the same server), hash verification provides an independent control.

**Residual Risk:** If checksums and signatures are fetched from the same compromised mirror, both can be replaced. Out-of-band checksum distribution (e.g., separate secure channel, signed release notes) is required for full protection.

### 4.4 Supply Chain Implant — Artifact Substitution

**Description:** An attacker substitutes a backdoored artifact at the point of build, packaging, or distribution, before signing occurs.

**Controls:** (1) If the implant is known malware, ClamAV detects it. (2) VirusTotal reputation may flag the hash. (3) Static inspection may detect suspicious indicators. (4) Reproducible build verification (Phase II) would detect divergence from expected build output.

**Residual Risk:** Novel implants with no malware signatures, not in VT database, and no detectable indicators pass through veriscan. This is an acknowledged limitation.

### 4.5 Supply Chain Implant — Signing Key Compromise

**Description:** An attacker obtains the legitimate signing key (through theft, weak passphrase, or insider access) and uses it to sign a malicious artifact.

**Controls:** (1) Fingerprint pinning (`allow_signers`) limits which keys are trusted; key rotation requires an operator update. (2) VirusTotal reputation may flag the hash of the malicious artifact independently of signing. (3) ClamAV may detect known malware patterns.

**Residual Risk:** An attacker with the signing key who produces novel malware will produce a legitimately-signed artifact that passes signature verification. ClamAV and VT provide partial mitigation only. Organizational key management controls are the primary defense.

### 4.6 Policy Weakening

**Description:** An attacker or insider modifies a policy file to weaken controls (e.g., set `require_signature: false`, clear `allow_signers`, or set `malware_failure_is_fatal: false`).

**Controls:** (1) Policy digest is recorded in every report; changes are detectable by comparing digests across runs. (2) Policy files should be stored in a version-controlled, access-controlled repository. (3) The `policy-validate` subcommand can be used to audit policy files.

**Residual Risk:** Policy tampering is detectable after the fact via digest comparison but not prevented by veriscan itself. Access controls on policy files are the operator's responsibility.

### 4.7 Report Tampering

**Description:** An attacker modifies a JSON report after generation to falsify verification results.

**Controls:** Evidence `deterministic_id` fields allow consumers to recompute the hash of each evidence record and detect modification. The policy digest in the report binds the verdict to a specific policy.

**Residual Risk:** An attacker with write access to the report can modify both the evidence content and its `deterministic_id`. Full report integrity requires storing reports in a write-once or signed storage system (outside veriscan's scope).

### 4.8 In-Pipeline Artifact Mutation

**Description:** An attacker with access to the filesystem on which veriscan runs modifies the artifact between pipeline stages (e.g., via a race condition or filesystem hook).

**Controls:** The orchestrator calls `assert_no_mutation()` after the hash, signature, malware, and inspect stages — the stages that read artifact content — re-computing the artifact SHA-256 and comparing it to the value recorded at acquisition. Any change aborts the run with a pipeline error: the process exits with code 99 and no report is emitted.

**Residual Risk:** An attacker who can modify the artifact and also modify the baseline hash stored in the `AcquireResult` struct (i.e., an attacker with memory write access to the veriscan process) can bypass this control. This requires OS-level compromise and is treated as out of scope.

### 4.9 ClamAV Evasion

**Description:** Malware uses packing, encryption, obfuscation, or polymorphism to evade ClamAV signature-based detection.

**Controls:** (1) Shannon entropy detection flags high-entropy (potentially packed) artifacts. (2) VirusTotal provides multi-engine reputation as a complementary control. (3) Static inspection detects generic suspicious indicators.

**Residual Risk:** Novel packers not in ClamAV's detection database, and malware specifically designed to evade signature detection, may not be detected. This is a fundamental limitation of signature-based detection.

### 4.10 Path Traversal in Bundle

**Description:** A maliciously crafted bundle manifest references files outside the bundle directory using `../` sequences or absolute paths.

**Controls:** `safe_bundle_path()` rejects any relative path containing `..` or beginning with `/`. The bundle directory is canonicalized before use to resolve symlinks.

**Residual Risk:** Canonicalization occurs after the check; platform-specific path handling edge cases (e.g., Windows drive letters) may require additional testing.

### 4.11 Log Injection via Artifact Content

**Description:** Artifact content (filenames, string extraction output) is reflected into log messages and could inject false log entries or escape structured JSON logging.

**Controls:** Tracing's structured logging serializes all field values, including strings derived from artifact content. Bounded string extraction (`max_inspection_strings`, `max_subprocess_output_bytes`) limits the volume of artifact-derived data in logs.

**Residual Risk:** Unicode control characters in artifact filenames may render unexpectedly in terminal output. This does not affect the JSON report, which is properly escaped.

---

## 5. Controls Implemented

| Control | Stage | Mechanism |
|---|---|---|
| Hash integrity | Hash | SHA-256 and SHA-512 computation + expected value comparison |
| In-pipeline mutation detection | Hash / Signature / Malware / Inspect | `assert_no_mutation()` re-checks SHA-256 after each content-reading stage |
| PGP signature verification | Signature | `sequoia-openpgp` detached signature verification |
| Signer fingerprint pinning | Signature | `allow_signers` list; signers not listed are rejected |
| Known malware detection | Malware | ClamAV subprocess with bounded output and cleared environment |
| Reputation check | Reputation | VirusTotal v3 hash-only lookup with local cache |
| File type control | Inspect / Policy | Magic-byte detection + `deny_file_types` list |
| Entropy flagging | Inspect / Policy | Shannon entropy threshold; policy rules on `high_entropy` |
| Suspicious indicator detection | Inspect | URL, PowerShell keyword, shell pattern, base64 blob scanning |
| Policy enforcement | Policy | Declarative YAML decision matrix; mandatory invariants |
| Fail-closed | All | Tool absence produces UNVERIFIED or FAILED, never silent pass |
| No artifact execution | All | Artifact bytes are read only; no execution at any stage |
| Secret exclusion from logs | Reputation | API key from env var; never logged, serialized, or included in reports |
| Subprocess isolation | Malware | Clear environment; absolute path; bounded output; timeout |
| Path traversal prevention | Bundle | `safe_bundle_path()` rejects `..` and absolute paths |
| Policy digest binding | Policy / Report | Policy SHA-256 digest recorded in every report |
| Evidence tamper detection | Evidence | `deterministic_id` SHA-256 over canonical evidence representation |

---

## 6. STRIDE Analysis

| Category | Threat | Veriscan Control | Notes |
|---|---|---|---|
| **Spoofing** | Attacker spoofs artifact origin | PGP signature + signer fingerprint pinning | Requires compromise of pinned signing key to bypass |
| **Spoofing** | Attacker spoofs a trusted mirror | Hash verification + signature verification | Mirror substitution detected by hash mismatch or sig failure |
| **Tampering** | Artifact tampered in transit | SHA-256 / SHA-512 hash verification | Requires expected checksums to be provided out-of-band |
| **Tampering** | Artifact tampered on disk between stages | `assert_no_mutation()` after the hash, signature, malware, and inspect stages | Detects file system race conditions |
| **Tampering** | Policy file tampered to weaken controls | Policy digest recorded in report | Tamper detectable post-hoc; prevention requires access controls |
| **Tampering** | Evidence record tampered post-generation | `deterministic_id` in each evidence item | Full prevention requires signed/immutable report storage |
| **Repudiation** | Operator denies a verification run occurred | JSON report with run UUID and timestamp | Reports must be stored in append-only or write-once systems |
| **Repudiation** | Operator denies which policy was applied | Policy digest in report + `policy-validate` command | Policy version and digest are bound to every verdict |
| **Information Disclosure** | API key leaked in logs or reports | Key from env var only; never serialized or logged | Key appears only in the HTTP header during the API call |
| **Information Disclosure** | Artifact content leaked to external services | Hash-only VT lookup; ClamAV is local | Artifact bytes never leave the local host |
| **Denial of Service** | Malformed artifact hangs veriscan | Bounded extraction (`max_inspection_strings`); subprocess timeout | Entropy sampling bounded to `entropy_sample_bytes` |
| **Denial of Service** | ClamAV subprocess hangs | `subprocess_timeout_seconds` with `tokio::time::timeout` | Returns `ScanError` on timeout, not a hang |
| **Elevation of Privilege** | Artifact execution during scan | Static-only analysis; no `exec()` calls on artifact | Verified by code review; ClamAV reads bytes via subprocess |
| **Elevation of Privilege** | Path traversal in bundle | `safe_bundle_path()` rejects `../` and absolute paths | Bundle base is canonicalized before any path joins |

---

## 7. Trust Boundaries

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │ UNTRUSTED ZONE                                                          │
 │                                                                         │
 │  [Artifact]  [Signature File]  [Checksum Files]  [Bundle Directory]    │
 │      └────────────────────────────────────────────┘                    │
 │                         │                                               │
 │              TRUST BOUNDARY (verification)                              │
 │─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
 │                         ▼                                               │
 │ VERISCAN PROCESS                                                        │
 │  ┌────────────────────────────────────────────────────────────────┐    │
 │  │  Pipeline stages (pure Rust; no artifact execution)            │    │
 │  │  ClamAV subprocess (cleared env; absolute path; bounded)       │    │
 │  │  VT API client (hash only; key from env)                       │    │
 │  └────────────────────────────────────────────────────────────────┘    │
 │                         │                                               │
 │              TRUST BOUNDARY (output)                                    │
 │─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
 │                         ▼                                               │
 │ TRUSTED OUTPUT ZONE                                                     │
 │  [JSON Report]  [Markdown Report]  [Exit Code]  [Audit Log]            │
 │                                                                         │
 └────────────────────────────────────────────────────────────────────────┘
```

**Inputs crossing the inbound boundary:** Artifact bytes, signature bytes, checksum values, public key material, bundle manifest content.

**Inputs NOT crossing the boundary:** Private key material (only public keys are loaded), API keys (read from environment, not from any untrusted input), executable content of the artifact.

**Outputs crossing the outbound boundary:** SHA-256 hash of the artifact (to VirusTotal API), structured verification reports, exit code, audit log entries.

---

## 8. Out-of-Scope Threats

The following threats are explicitly out of scope for Veriscan and must be addressed through organizational or infrastructure controls:

| Threat | Rationale |
|---|---|
| Zero-day malware with no signatures | Signature-based detection is inherently reactive. Novel malware not in ClamAV or VT databases is not detected. |
| Nation-state implants in legitimately-signed upstream releases | If the upstream vendor's signing key and build system are both compromised, veriscan cannot distinguish the malicious release from a legitimate one. Phase II reproducible builds provide partial mitigation. |
| Compromise of the veriscan host OS | An attacker with root access to the host running veriscan can interfere with the process, modify files, or inject into the pipeline in ways veriscan cannot detect. |
| Compromise of the ClamAV binary | Veriscan trusts the ClamAV binary at the configured absolute path. Binary substitution of ClamAV itself is not detected. |
| Compromise of the VirusTotal infrastructure | VT is used as a reputation source. A compromised VT could return false negatives. VT is not the primary control; signature and hash verification are. |
| Side-channel attacks on PGP key material | Key management is outside veriscan's scope. HSMs and secure key storage are the deploying organization's responsibility. |
| Denial of service against the deployment environment | Veriscan is a verification gate; it does not protect the runtime environment from DoS. |
| Insider threats with legitimate signing key access | Fingerprint pinning and VirusTotal/ClamAV checks provide partial mitigation. Organizational key management and access control are the primary controls. |
| Malware embedded in ClamAV virus database updates | Database integrity is managed by the ClamAV project and the deploying organization. |

---

## 9. Mitigations and Residual Risk

### 9.1 For Hash-Only Attacks (No Signature Checking)

**Mitigation:** Enable `require_signature: true` and populate `allow_signers` with the fingerprints of authorized signing keys. Deploy `contractor_strict.yaml` or `airgapped.yaml` policy in high-assurance environments.

**Residual Risk:** If the signing key is compromised, signature verification cannot distinguish malicious from legitimate artifacts.

### 9.2 For Novel Malware (Signature Evasion)

**Mitigation:** Enable entropy flagging (`max_entropy_threshold`); require reputation check (`reputation_required: true`); enable static inspection indicators review.

**Residual Risk:** Novel, targeted malware designed to evade all three complementary controls may pass. No signature-based tool eliminates this risk.

### 9.3 For Policy Weakening (Insider)

**Mitigation:** Store policy files in a version-controlled, access-controlled repository. Require peer review for policy changes. Audit policy digest values in reports against a known-good digest baseline.

**Residual Risk:** An insider with both repository access and the ability to deploy modified policies can weaken controls. Separation of duties is the primary organizational control.

### 9.4 For Air-Gapped Environment Bypass

**Mitigation:** Use `airgapped.yaml` policy (`allow_network: false`). This makes any attempt to acquire an artifact via URL a hard error (exit 99); the reputation stage does not attempt a VirusTotal lookup and instead skips gracefully with an `Unknown` status recorded in the report. Only offline bundle verification is supported.

**Residual Risk:** If the bundle itself is created with a compromised signing key, offline bundle verification cannot detect malicious content beyond what ClamAV and static inspection reveal.

### 9.5 For Report Integrity

**Mitigation:** Store JSON reports in a write-once, append-only storage system (e.g., S3 with object lock, a signed audit log system). Use the `deterministic_id` field in each evidence item to detect post-generation tampering.

**Residual Risk:** An attacker who controls both the report storage and can recompute deterministic IDs (the hash algorithm is not secret) can fabricate a coherent false report. Signing reports cryptographically (out of scope for Phase I) would eliminate this residual risk.
