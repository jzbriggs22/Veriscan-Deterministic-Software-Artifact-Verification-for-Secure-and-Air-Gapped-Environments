# Evidence Model

## Veriscan Audit-Grade Evidence Chain

**Version:** 1.0

---

## Overview

Every verification run performed by veriscan produces a structured, ordered sequence of evidence records. These records capture the inputs, outputs, and tool versions of each pipeline stage in a form that supports:

- Independent reconstruction of the verification reasoning.
- Downstream tamper detection of individual evidence records.
- Long-term archival for audit and compliance reporting.
- Machine-readable consumption by SIEM, GRC, and reporting systems.

The evidence model is designed to answer the question: *"Given only the JSON report, can an auditor independently verify that the stated verdict follows from the stated evidence?"*

---

## 1. EvidenceItem Schema

Each evidence item is an instance of the `EvidenceItem` struct defined in `src/evidence.rs`. The JSON serialization is stable (part of the v1.0 report schema).

### Fields

| Field | JSON Type | Rust Type | Purpose |
|---|---|---|---|
| `timestamp` | String | `String` | ISO 8601 UTC timestamp when this evidence was collected. Records when in wall-clock time the evidence was produced. |
| `stage_name` | String | `String` | Canonical name of the pipeline stage that produced this evidence. One of: `acquire`, `hash`, `signature`, `malware`, `inspect`, `reputation`, `policy`. |
| `inputs` | Object | `HashMap<String, String>` | Named string inputs to the stage. These are the values the stage operated on: artifact path, expected hash values, signature file path, key directory path, API source identifier. All values are strings; no sensitive values (keys, passwords) appear here. |
| `outputs` | Object | `HashMap<String, serde_json::Value>` | Named typed JSON outputs from the stage. Values may be strings, booleans, numbers, or arrays. Typed values avoid information loss that would occur with forced string serialization (e.g., boolean `true` vs. string `"true"`). |
| `tool_versions` | Object | `HashMap<String, String>` | Version strings of external tools invoked during this stage. Example: `{"clamscan": "ClamAV 1.0.3/26955"}`. Empty for pure-Rust stages. |
| `deterministic_id` | String | `String` | SHA-256 hex digest of the canonical representation of this evidence item. Computed at construction time and included in the record; allows downstream consumers to detect post-generation tampering. |

### Example EvidenceItem (Hash Stage)

```json
{
  "timestamp": "2025-01-15T14:32:01.123Z",
  "stage_name": "hash",
  "inputs": {
    "artifact_path": "/tmp/veriscan_a1b2c3/demo_artifact.tar.gz",
    "expected_sha256": "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
  },
  "outputs": {
    "sha256": "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
    "sha512": "b14a7b8059d9c055954c92674ce60032d1813f27952a4f31a0a4b9cee61c6e5...",
    "sha256_matched": true
  },
  "tool_versions": {},
  "deterministic_id": "f4a2b1c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"
}
```

---

## 2. Deterministic ID Computation

The `deterministic_id` is a SHA-256 digest that binds the identity of an evidence record to its content. It is computed at construction time inside `EvidenceItem::new()`.

### Canonical Form

The canonical string is constructed as a pipe-delimited sequence of tagged fields:

```
stage:<stage_name>|timestamp:<timestamp>|in:<k1>=<v1>|in:<k2>=<v2>|...|out:<k1>=<json_v1>|out:<k2>=<json_v2>|...
```

Construction rules:

1. Start with `stage:<stage_name>`.
2. Append `timestamp:<iso8601_timestamp>`.
3. Append all input fields as `in:<key>=<value>`, with keys sorted alphabetically.
4. Append all output fields as `out:<key>=<compact_json_value>`, with keys sorted alphabetically. Output values are serialized as compact (no whitespace) JSON.
5. Join all components with `|`.
6. Compute SHA-256 of the UTF-8 encoding of the joined string.
7. Hex-encode the digest.

### Example Canonical Form (Hash Stage)

```
stage:hash|timestamp:2025-01-15T14:32:01.123Z|in:artifact_path=/tmp/veriscan_a1b2c3/demo_artifact.tar.gz|in:expected_sha256=3a7bd3e2...|out:sha256="3a7bd3e2..."|out:sha256_matched=true|out:sha512="b14a7b80..."
```

### Why Key Sorting Matters

Without key sorting, the canonical form of the same evidence item could differ depending on hash map iteration order (which is non-deterministic in Rust's `HashMap`). Sorting ensures that two evidence items with identical logical content produce identical `deterministic_id` values regardless of insertion order.

### How to Verify a deterministic_id

Given a JSON report, an auditor can verify the `deterministic_id` of any evidence item by:

1. Extracting `stage_name`, `timestamp`, `inputs`, and `outputs`.
2. Sorting `inputs` keys alphabetically, constructing `in:<k>=<v>` pairs.
3. Sorting `outputs` keys alphabetically, constructing `out:<k>=<compact_json_v>` pairs where the value is compact JSON (no whitespace).
4. Joining all parts with `|`.
5. Computing SHA-256 of the joined string (UTF-8 encoded).
6. Comparing the hex-encoded result to the `deterministic_id` in the record.

Any discrepancy indicates the evidence record was modified after generation.

---

## 3. Stage-by-Stage Evidence Production

### Stage 1: Acquire

**Produced by:** `src/stages/acquire.rs::run()`

**Inputs recorded:**
- `source` — the original artifact source string (local path or URL)
- `local_path` — the path to the artifact on local disk after acquisition

**Outputs recorded:**
- `size_bytes` — artifact size in bytes (number)
- `sha256_at_acquire` — SHA-256 hash computed immediately after acquisition (string)
- `filename` — the filename component of the artifact path (string)
- `source_type` — `"local"` or `"url"` (string)

**Tool versions:** none (pure Rust)

**Evidential value:** Establishes the artifact identity (hash at acquisition) and provenance (source). The `sha256_at_acquire` value is the baseline for in-pipeline mutation detection.

---

### Stage 2: Hash

**Produced by:** `src/stages/hash.rs::run()`

**Inputs recorded:**
- `artifact_path` — path to the artifact
- `expected_sha256` — expected SHA-256 value if provided (omitted if not)
- `expected_sha512` — expected SHA-512 value if provided (omitted if not)

**Outputs recorded:**
- `sha256` — computed SHA-256 hex digest (string)
- `sha512` — computed SHA-512 hex digest (string)
- `sha256_matched` — whether computed SHA-256 matched the expected value (boolean, omitted if no expected value)
- `sha512_matched` — whether computed SHA-512 matched the expected value (boolean, omitted if no expected value)

**Tool versions:** none (pure Rust `sha2` crate)

**Evidential value:** Records the cryptographic identity of the artifact and whether it matches the operator's declared expected value. A `sha256_matched: false` output would appear in the evidence even though the pipeline halts with FAILED before reaching later stages; in practice, if this field is `false`, the pipeline returns FAILED and subsequent stages do not execute.

---

### Stage 3: Signature

**Produced by:** `src/stages/signature.rs`

**Case A — Verified:**

Inputs: `sig_path` (path to the signature file)

Outputs: `signature_status: "verified"`, `fingerprint` (signer key fingerprint, hex), `signer_uid` (PGP user ID string)

**Case B — Missing:**

Inputs: `sig_path: ""`

Outputs: `signature_status: "missing"`, `fingerprint: ""`, `detail: "No .sig or .asc file found adjacent to artifact"` (or similar)

**Case C — Invalid:**

Inputs: `sig_path` (path to the file that failed verification)

Outputs: `signature_status: "invalid"`, `fingerprint: ""`, `detail` (error message from sequoia-openpgp)

**Case D — Signer Not Allowed:**

Inputs: `sig_path`

Outputs: `signature_status: "signer_not_allowed"`, `fingerprint` (the signer's fingerprint that was not in the allowlist)

**Tool versions:** none (pure Rust sequoia-openpgp)

**Evidential value:** Records the cryptographic authenticity of the artifact. The fingerprint provides non-repudiable attribution to a specific signing key.

---

### Stage 4: Malware

**Produced by:** `src/stages/malware.rs`

**Case A — Clean:**

Inputs: `tool_path` (absolute path to clamscan binary)

Outputs: `scan_status: "clean"`, `scan_output_excerpt` (first 512 chars of clamscan stdout)

Tool versions: `{"clamscan": "<version string from clamscan --version>"}`

**Case B — Detected:**

Inputs: `tool_path`

Outputs: `scan_status: "detected"`, `detections` (array of detection name strings), `scan_output_excerpt` (first 1024 chars)

Tool versions: `{"clamscan": "<version>"}`

**Case C — Skipped (tool missing):**

Inputs: none

Outputs: `scan_status: "skipped"`, `reason: "clamscan not found at default paths"` (or similar)

Tool versions: none

**Case D — Error:**

Inputs: none

Outputs: `scan_status: "error"`, `reason: "Scan timed out after 120s"` (or similar error description)

Tool versions: captured if version was obtained before the error

**Evidential value:** Records the outcome of signature-based malware scanning, including the engine version (critical for audit reproducibility — the same scan on the same artifact with different database versions may produce different results). Detection names are included verbatim from ClamAV output.

---

### Stage 5: Inspect

**Produced by:** `src/stages/inspect.rs`

**Inputs recorded:**
- `artifact_path` — path to the artifact

**Outputs recorded:**
- `file_type` — detected file type string (e.g., `"ELF"`, `"ZIP"`, `"Shell Script"`)
- `entropy` — Shannon entropy value (number, 0.0–8.0)
- `entropy_flagged` — whether entropy exceeds the policy threshold (boolean)
- `indicator_count` — number of indicators found (number)
- `indicators` — array of indicator description strings (e.g., `"URL: https://example.com/payload"`, `"PowerShell keyword: IEX"`)
- `strings_sample` — first 20 extracted strings from the artifact (array of strings)

**Tool versions:** none (pure Rust)

**Evidential value:** Provides observable, measurable characteristics of the artifact's content without executing it. The `indicators` array records specific suspicious patterns found; the `strings_sample` provides context for analyst review. Shannon entropy quantifies the degree of compression or encryption of the artifact.

---

### Stage 6: Reputation

**Produced by:** `src/stages/reputation.rs`

**Case A — Checked (clean or malicious):**

Inputs: `sha256` (the artifact's SHA-256 hash), `source: "VirusTotal v3"` (or `"VirusTotal v3 (cached)"`)

Outputs: `reputation_status: "clean"` or `"malicious"`, `engines_total` (number), `engines_detected` (number), `reputation_label: "clean"` or `"malicious"`, `last_seen` (ISO 8601 timestamp, if available)

**Case B — Skipped (offline, no API key, not in database):**

Inputs: none

Outputs: `reputation_status: "skipped"`, `reason` (description string)

**Tool versions:** none (HTTP API call, not a subprocess)

**Note on API key:** The API key is deliberately excluded from all evidence records. It appears only in the HTTP Authorization header during the API call and is not recorded anywhere in the report or evidence.

**Evidential value:** Records whether the artifact's hash is known to the VirusTotal threat intelligence database. The `engines_total` and `engines_detected` values provide context for the verdict. Cache hits are noted with `"(cached)"` in the source field.

---

### Stage 7: Policy

**Produced by:** `src/stages/policy.rs::evaluate()`

**Inputs recorded:**
- `policy_name` — the policy name string
- `policy_version` — the policy version string
- `policy_digest` — SHA-256 of the serialized policy (hex)

**Outputs recorded:**
- `verdict` — the final verdict label: `"VERIFIED"`, `"UNVERIFIED"`, or `"FAILED"`
- `rules_evaluated` — total number of rules evaluated (number)
- `decision_trace` — full array of trace entries, each containing: `rule_description`, `condition`, `matched` (boolean), `verdict` (string or null)

**Tool versions:** none (pure Rust)

**Evidential value:** Records the complete decision-making process. Every rule evaluated — whether it matched or not — appears in the trace. The policy digest binds the verdict to the exact policy configuration. An auditor can reconstruct the verdict from the trace without re-running the tool.

---

## 4. Chain-of-Custody Considerations

### Immutability of Evidence After Generation

Evidence items are constructed once and never modified. The `EvidenceItem::new()` constructor computes the `deterministic_id` synchronously at construction time. After the constructor returns, the fields (including `deterministic_id`) are immutable.

### Ordering

Evidence items are appended to the `all_evidence` vector by the orchestrator in pipeline stage order. The JSON report's `evidence` array preserves this order. Auditors can verify that evidence was collected in the expected stage sequence by examining the `stage_name` fields in order.

### Completeness

A complete pipeline run should produce exactly one evidence item per executed stage. If a stage returns early (e.g., ClamAV tool missing), it still produces an evidence item recording the `"skipped"` or `"error"` outcome. The absence of an evidence item for a stage that should have run indicates a pipeline error (exit code 99).

### Time Correlation

Each `EvidenceItem.timestamp` records the wall-clock UTC time when that evidence was collected. The `JsonReport.timestamp` field records the time the report was built (after all stages complete). The `JsonReport.elapsed_secs` field records the total pipeline duration. These values allow auditors to correlate veriscan runs with other system event logs (SIEM, access logs, deployment records).

---

## 5. Preserving and Archiving Evidence for Audits

### Recommended Storage

For compliance environments, veriscan JSON reports should be stored in an append-only, access-controlled repository. Options include:

- **Object storage with object lock (S3 Object Lock, GCS Object Lock):** Prevents modification or deletion for a defined retention period.
- **Signed audit log systems (e.g., AWS CloudTrail with log file validation):** Each log entry is cryptographically signed.
- **Git-based audit logs:** JSON reports committed to a signed git repository with branch protection.
- **Write-once media:** For air-gapped environments, burned to optical media or written to WORM tape.

### Recommended Retention

Retain JSON reports for at least as long as the compliance framework requires:
- NIST SP 800-53 AU-11: retention period specified by organizational policy (typically 1–3 years).
- FedRAMP: at minimum 1 year online, 3 years archival.
- DoD IL4/5 environments: follow applicable STIG and data handling requirements.

### What to Archive

For each veriscan run, archive:
1. The JSON report (`--report-json` output).
2. The policy file used, identified by its digest as printed by `veriscan policy-validate`.
3. The command invocation (captured from CI/CD pipeline logs) including all CLI arguments.
4. If ClamAV was used: the ClamAV database version recorded in the evidence `tool_versions` field.

The Markdown report (`--report-md`) is supplementary human-readable documentation; it is derived from the JSON report and does not carry additional evidentiary weight.

### Verifying Archive Integrity

To verify a JSON report has not been modified since archival:
1. Compute SHA-256 of the JSON report file.
2. Compare to a trusted reference (e.g., hash recorded in the audit log system, or hash of the original file committed to a signed git repository).

To verify individual evidence records within the report:
1. For each evidence item, reconstruct the canonical form per Section 2 above.
2. Compute SHA-256 of the canonical form.
3. Compare to the `deterministic_id` in the record.

---

## 6. Evidence in the JSON Report

The `evidence` array appears at the top level of the JSON report. It is present in every report, including FAILED reports produced by early pipeline termination.

### Report Top-Level Structure (abridged)

```json
{
  "schema_version": "1.0",
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-01-15T14:32:05.456Z",
  "elapsed_secs": 4.333,
  "artifact": { ... },
  "verdict": {
    "status": "VERIFIED",
    "reason": null,
    "exit_code": 0
  },
  "hashes": { ... },
  "signature": { ... },
  "malware_scan": { ... },
  "reputation": { ... },
  "inspection": { ... },
  "policy": {
    "name": "contractor_strict",
    "version": "1.0",
    "digest": "a1b2c3d4e5f6..."
  },
  "decision_trace": [ ... ],
  "evidence": [
    { "stage_name": "acquire", "timestamp": "...", "inputs": {...}, "outputs": {...}, "tool_versions": {}, "deterministic_id": "..." },
    { "stage_name": "hash",    "timestamp": "...", "inputs": {...}, "outputs": {...}, "tool_versions": {}, "deterministic_id": "..." },
    { "stage_name": "signature","timestamp": "...", "inputs": {...}, "outputs": {...}, "tool_versions": {}, "deterministic_id": "..." },
    { "stage_name": "malware", "timestamp": "...", "inputs": {...}, "outputs": {...}, "tool_versions": {"clamscan": "..."}, "deterministic_id": "..." },
    { "stage_name": "inspect", "timestamp": "...", "inputs": {...}, "outputs": {...}, "tool_versions": {}, "deterministic_id": "..." },
    { "stage_name": "reputation","timestamp":"...","inputs": {...}, "outputs": {...}, "tool_versions": {}, "deterministic_id": "..." },
    { "stage_name": "policy",  "timestamp": "...", "inputs": {...}, "outputs": {...}, "tool_versions": {}, "deterministic_id": "..." }
  ],
  "tool_versions": {},
  "warnings": []
}
```

### Schema Stability

The JSON report schema is versioned at `"schema_version": "1.0"`. The schema is additive-only; future versions may add fields but will not remove or rename existing fields. Consumers should treat unknown fields as ignorable extensions.

---

## 7. Tamper Detection in Evidence Records

### What Can Be Detected

The `deterministic_id` mechanism detects modification of the following evidence record fields after generation:
- `stage_name`
- `timestamp`
- Any key or value in `inputs`
- Any key or value in `outputs`

### What Cannot Be Detected Without External Reference

- Addition of entirely new evidence items to the `evidence` array.
- Removal of existing evidence items from the `evidence` array.
- Modification of the `deterministic_id` field itself (since a forger can recompute the correct ID after modifying the record).

Full protection against these attack vectors requires storing the JSON report's own SHA-256 hash in an external trusted system (e.g., signing the report, or recording the report hash in a tamper-evident audit log).

### Practical Verification Procedure

Security operations personnel can verify a specific evidence record as follows:

```bash
# Extract an evidence item from the report
jq '.evidence[1]' report.json > hash_evidence.json

# Reconstruct the canonical form manually or via script
STAGE=$(jq -r '.stage_name' hash_evidence.json)
TS=$(jq -r '.timestamp' hash_evidence.json)
# ... build canonical string per Section 2 ...

# Compute expected deterministic_id
echo -n "<canonical_string>" | sha256sum

# Compare to recorded value
jq -r '.deterministic_id' hash_evidence.json
```

A mismatch indicates the evidence record was modified after the veriscan run that produced it.

### Limitations and Recommendations

The `deterministic_id` provides evidence integrity at the record level. For full chain-of-custody integrity, organizations should:

1. Sign JSON reports cryptographically after generation (e.g., using PGP detached signature over the JSON file).
2. Store the SHA-256 of each report in a separate, independent audit log.
3. Implement write-once storage for the report archive.
4. Periodically re-verify archived reports using the `deterministic_id` mechanism to detect storage-layer tampering.
