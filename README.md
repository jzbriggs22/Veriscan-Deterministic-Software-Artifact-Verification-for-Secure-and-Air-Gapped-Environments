# veriscan

**Defense-grade deterministic software artifact verification for secure and air-gapped environments.**

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)]()
[![Language: Rust](https://img.shields.io/badge/language-Rust-orange.svg)]()

---

## Overview

`veriscan` is a contractor-grade CLI tool that validates the **integrity**, **authenticity**, and **risk posture** of software artifacts through a mandatory, ordered verification pipeline. Every decision is backed by structured, auditable evidence. No stage can be skipped.

Designed for:
- SOC analysts verifying vendor deliverables before staging
- DevSecOps teams gating artifacts in CI/CD pipelines
- Air-gapped environments verifying offline deliveries
- Security auditors reviewing evidence of verification
- Defense contractors requiring supply-chain verification controls

---

## Quick Start

```bash
# Build
cargo build --release

# Verify a local file (default policy)
./target/release/veriscan verify /path/to/artifact.tar.gz

# Verify with a specific policy and generate reports
./target/release/veriscan verify \
    --policy policies/contractor_strict.yaml \
    --expected-sha256 <hex> \
    --trusted-keys /path/to/keys/ \
    --sig artifact.tar.gz.asc \
    --report-json report.json \
    --report-md report.md \
    /path/to/artifact.tar.gz

# Verify an offline bundle
./target/release/veriscan verify \
    --policy policies/airgapped.yaml \
    --offline /path/to/bundle/

# Create an offline bundle
./target/release/veriscan bundle create \
    --artifact artifact.tar.gz \
    --keys /path/to/keys/ \
    --signing-key /path/to/secret.asc \
    --out /path/to/bundle/

# Validate a policy file
./target/release/veriscan policy-validate policies/contractor_strict.yaml

# Print report schema
./target/release/veriscan report-schema
```

---

## Exit Codes

| Code | Meaning | CI action |
|------|---------|-----------|
| `0`  | **VERIFIED** — all required checks passed | Continue |
| `10` | **UNVERIFIED** — checks incomplete (tool missing, optional) | Warn or block |
| `20` | **FAILED** — definitive failure (hash mismatch, malware, invalid sig) | Block |
| `99` | **Tool error** — policy invalid, I/O failure, etc. | Investigate |

---

## Pipeline Stages (mandatory, ordered)

```
Acquire → Hash → Signature → Malware → Inspect → Reputation → Policy
```

1. **Acquire** — Download (URL) or read (local path) the artifact
2. **Hash** — Compute SHA-256/SHA-512; verify against expected checksums
3. **Signature** — PGP detached signature verification with key pinning
4. **Malware** — ClamAV subprocess scan (bounded, no shell, no inherited env)
5. **Inspect** — File type, Shannon entropy, string indicators (no execution)
6. **Reputation** — VirusTotal hash-only lookup (cached, never uploads)
7. **Policy** — Decision matrix evaluation → typed verdict

Stages cannot be reordered, skipped, or bypassed by CLI flags. Artifact hash is verified before and after each stage to detect in-pipeline mutation.

---

## Policies

Policies are YAML files that define the verification behaviour. Four policies are included:

| Policy | Use Case |
|--------|----------|
| `default.yaml` | General verification (balanced) |
| `contractor_strict.yaml` | High-assurance defense environments |
| `airgapped.yaml` | No-network, air-gapped environments |
| `ci_gate.yaml` | Automated CI/CD pipeline gating |

---

## Offline Verification Bundles

For air-gapped environments, create a bundle once and verify offline:

```
bundle/
  artifact.tar.gz          # The artifact
  artifact.tar.gz.sha256   # SHA-256 checksum
  artifact.tar.gz.sha512   # SHA-512 checksum
  artifact.tar.gz.sig      # PGP detached signature
  trusted_keys/
    signing_pub.asc         # Trusted public keys
  bundle.manifest.json     # Lists all files + their SHA-256
  bundle.manifest.sig      # PGP signature over the manifest
```

**Verification order:**
1. Verify `bundle.manifest.sig` over `bundle.manifest.json` (trusted keys)
2. Verify SHA-256 of every file listed in manifest
3. Verify artifact signature using trusted keys
4. Run full pipeline on the verified artifact

---

## Threat Model

### Defended Against

- Corrupted downloads and bit flips
- Mirror tampering / MITM leading to modified artifacts
- Unauthorized modification of artifacts in transit
- Known malware (signature-based, ClamAV)
- Known-bad reputation hashes (VirusTotal)
- Accidental introduction of unsigned/untrusted executables

### Not Defended Against

- Zero-days or novel malware with no signatures
- Nation-state implants in signed upstream releases
- Insider threats with legitimate access to signing keys
- Malicious compilers/toolchains (unless reproducible build workflows are configured)

See [docs/threat_model.md](docs/threat_model.md) for the full threat model.

---

## Reports

Every run produces:

- **JSON report** — machine-readable, stable schema (v1.0)
- **Markdown report** — human-readable summary for analysts

Example JSON report fields:
```json
{
  "schema_version": "1.0",
  "run_id": "<uuid>",
  "verdict": { "status": "VERIFIED", "exit_code": 0 },
  "hashes": { "sha256": "...", "sha512": "..." },
  "signature": { "status": "verified", "fingerprint": "...", "signer_uid": "..." },
  "malware_scan": { "status": "clean", "engine": "ClamAV" },
  "reputation": { "status": "clean", "engines_total": 72, "engines_detected": 0 },
  "decision_trace": [...],
  "evidence": [...]
}
```

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `clap` | CLI argument parsing |
| `serde` / `serde_json` / `serde_yaml` | Serialization |
| `sha2` | SHA-256/512 hashing |
| `sequoia-openpgp` | PGP signature verification (pure-Rust) |
| `reqwest` | HTTP downloads and VT API |
| `tokio` | Async runtime |
| `chrono` | Timestamps |
| `tracing` | Structured logging |
| `uuid` | Correlation IDs |
| `regex` | Indicator scanning |

External tools (optional):
- `clamscan` (ClamAV) — malware scanning
- `gpg` (GnuPG) — for creating demo bundles/signatures

---

## Building

```bash
# Debug build
cargo build

# Release build (stripped, LTO)
cargo build --release

# Run tests
cargo test

# Demo environment (requires Docker)
cd demo && docker-compose up
```

**System requirements:**
- Rust 1.70+
- No C library dependencies (uses pure-Rust crypto backend)
- Optional: ClamAV (`clamscan`) for malware scanning

---

## Documentation

| Document | Description |
|----------|-------------|
| [SECURITY.md](SECURITY.md) | Security policy, vulnerability reporting |
| [COMPLIANCE.md](COMPLIANCE.md) | Compliance posture and NIST mappings |
| [WHITEPAPER.md](WHITEPAPER.md) | Technical whitepaper |
| [CAPABILITY_STATEMENT.md](CAPABILITY_STATEMENT.md) | Subcontractor capability statement |
| [SOW_TEMPLATE.md](SOW_TEMPLATE.md) | Statement of Work template |
| [docs/architecture.md](docs/architecture.md) | Architecture and design |
| [docs/threat_model.md](docs/threat_model.md) | Threat model and trust boundaries |
| [docs/evidence_model.md](docs/evidence_model.md) | Evidence model and audit chain |
| [docs/demo_guide.md](docs/demo_guide.md) | Step-by-step demo instructions |
| [docs/controls/nist_800_53_rev5.md](docs/controls/nist_800_53_rev5.md) | NIST SP 800-53 Rev5 control mapping |
| [docs/controls/nist_800_161.md](docs/controls/nist_800_161.md) | NIST SP 800-161 SCRM mapping |

---

## License

`veriscan` is dual-licensed under MIT and Apache 2.0. See LICENSE-MIT and LICENSE-APACHE.

---

*This tool is designed for authorized verification workflows in regulated environments. It does not execute artifacts and never uploads files to external services.*