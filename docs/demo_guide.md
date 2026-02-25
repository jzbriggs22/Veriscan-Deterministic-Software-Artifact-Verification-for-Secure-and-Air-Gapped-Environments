# Demo Guide

## Veriscan Step-by-Step Demonstration

**Version:** 1.0

---

## Prerequisites

### Required

- **Rust 1.70+** — Install via [rustup.rs](https://rustup.rs)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  rustc --version   # should be 1.70.0 or higher
  ```

- **GnuPG (gpg)** — Used to generate signing keys for demo fixtures.
  ```bash
  # Linux (Debian/Ubuntu)
  sudo apt-get install -y gnupg2

  # macOS
  brew install gnupg

  # Verify
  gpg --version
  ```

### Optional (Enables Additional Scenarios)

- **ClamAV** — Required for malware scan scenarios (Scenario 4).
  ```bash
  # Linux (Debian/Ubuntu)
  sudo apt-get install -y clamav
  sudo freshclam   # Update virus definitions

  # macOS
  brew install clamav
  freshclam

  # Verify
  clamscan --version
  ```

- **Docker + Docker Compose** — For the containerized all-in-one demo.
  ```bash
  docker --version
  docker compose version
  ```

- **VirusTotal API key** — For Scenario 5 reputation checks.
  ```bash
  export VT_API_KEY="your_key_here"
  ```

- **jq** — For formatting JSON report output in examples.
  ```bash
  # Linux
  sudo apt-get install -y jq
  # macOS
  brew install jq
  ```

---

## Quick Start

### 1. Build

```bash
cd /path/to/veriscan

# Debug build (faster to compile)
cargo build

# Release build (production; stripped, LTO-optimized)
cargo build --release

# Verify binary
./target/release/veriscan --version
./target/release/veriscan --help
```

### 2. Validate a Policy File

```bash
./target/release/veriscan policy-validate policies/default.yaml
# Output: Policy 'default' v1.0 is valid.
# Digest: <sha256 hex>

./target/release/veriscan policy-validate policies/contractor_strict.yaml
# Output: Policy 'contractor_strict' v1.0 is valid.
```

### 3. Print the Report Schema

```bash
./target/release/veriscan report-schema
```

### 4. Basic Verification (No Expected Hash)

```bash
./target/release/veriscan verify /path/to/any/file.txt
```

This runs the full pipeline. Without an expected hash, the Hash stage records the computed values but cannot verify against an expected value. Without a signature file, signature status is `missing`. The verdict depends on policy settings.

---

## Setting Up Demo Fixtures

The demo scripts in `demo/scripts/` require fixture files. Generate them with:

```bash
cd demo
bash scripts/make_bundle.sh
```

This script:
1. Generates a GPG key pair (demo keys only — do not use in production).
2. Creates a demo artifact (`demo_artifact.tar.gz`).
3. Signs the artifact.
4. Generates checksum files.
5. Creates an offline verification bundle.
6. Creates tampered and unsigned variants for failure scenarios.
7. Writes the EICAR test string to `fixtures/malware_sim/eicar.com.txt`.

Expected output:
```
[make_bundle] Generating demo GPG key...
[make_bundle] Creating demo artifact...
[make_bundle] Signing artifact...
[make_bundle] Creating offline bundle...
[make_bundle] Creating tampered fixture...
[make_bundle] Creating unsigned fixture...
[make_bundle] Creating EICAR test fixture...
[make_bundle] Done. Fixtures at: demo/fixtures/
```

---

## Scenario 1: VERIFIED Artifact

**Purpose:** Demonstrate a fully passing verification with valid signature and checksums.

**Expected verdict:** VERIFIED (exit code 0)

### Command

```bash
GOOD="demo/fixtures/good/demo_artifact.tar.gz"
EXPECTED_SHA256=$(cat "${GOOD}.sha256")

./target/release/veriscan verify \
    --policy policies/default.yaml \
    --expected-sha256 "${EXPECTED_SHA256}" \
    --trusted-keys demo/fixtures/good/trusted_keys \
    --sig "${GOOD}.asc" \
    --report-json demo/out/scenario1_verified.json \
    --report-md  demo/out/scenario1_verified.md \
    "${GOOD}"

echo "Exit code: $?"
```

### Expected Output

```
INFO  Verification pipeline started
INFO  Stage complete  stage=acquire
INFO  Digests computed  sha256=3a7bd3e2...  sha512=b14a7b80...
INFO  SHA-256 verified against expected
INFO  Stage complete  stage=hash
INFO  Signature verified  fingerprint=ABCDEF...  uid="Demo User <demo@example.com>"
INFO  Stage complete  stage=signature
INFO  clamscan completed  exit_code=0   (or: clamscan not found)
INFO  Stage complete  stage=malware
INFO  Inspection complete  file_type=GZIP  entropy=5.234  entropy_flagged=false
INFO  Stage complete  stage=inspect
INFO  Stage complete  stage=reputation
INFO  Policy evaluation complete  verdict=VERIFIED
INFO  Stage complete  stage=policy

╔══════════════════════════════════════╗
║  VERDICT:         VERIFIED           ║
╚══════════════════════════════════════╝

SHA-256: 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b
Signature: verified
Malware scan: clean  (or: tool_missing if ClamAV not installed)
Reputation: unknown  (or: clean if VT_API_KEY set)
Exit code: 0
```

### Inspect the Report

```bash
jq '.verdict' demo/out/scenario1_verified.json
# { "status": "VERIFIED", "reason": null, "exit_code": 0 }

jq '.signature' demo/out/scenario1_verified.json
# { "status": "verified", "signer_uid": "Demo User <demo@example.com>", "fingerprint": "ABCDEF..." }

jq '[.evidence[] | .stage_name]' demo/out/scenario1_verified.json
# ["acquire","hash","signature","malware","inspect","reputation","policy"]
```

---

## Scenario 2: FAILED — Tampered Artifact

**Purpose:** Demonstrate detection of a tampered artifact where the computed SHA-256 does not match the expected value.

**Expected verdict:** FAILED (exit code 20)

### What Makes This Scenario Work

The tampered fixture (`demo/fixtures/tampered/demo_artifact.tar.gz`) has extra bytes appended to it. The test uses the checksum from the *original* good artifact as the expected value, so the hash verification fails immediately.

### Command

```bash
TAMPERED="demo/fixtures/tampered/demo_artifact.tar.gz"
ORIGINAL_SHA256=$(cat "demo/fixtures/good/demo_artifact.tar.gz.sha256")

./target/release/veriscan verify \
    --policy policies/default.yaml \
    --expected-sha256 "${ORIGINAL_SHA256}" \
    --trusted-keys demo/fixtures/tampered/trusted_keys \
    --report-json demo/out/scenario2_tampered.json \
    --report-md  demo/out/scenario2_tampered.md \
    "${TAMPERED}" || true

echo "Exit code: $?"   # Expected: 20
```

### Expected Output

```
INFO  Verification pipeline started
INFO  Stage complete  stage=acquire
ERROR stage=hash  error="Hash mismatch: expected '3a7bd3e2...', got 'f1e2d3c4...'"

╔══════════════════════════════════════╗
║  VERDICT:          FAILED            ║
╚══════════════════════════════════════╝

Reason: Hash mismatch: expected '3a7bd3e2360a...', got 'f1e2d3c4b5a6...'
Exit code: 20
```

### Key Evidence Fields

```bash
jq '.verdict' demo/out/scenario2_tampered.json
# { "status": "FAILED", "reason": "Hash mismatch: expected '3a7bd...' got 'f1e2...'", "exit_code": 20 }

jq '.hashes' demo/out/scenario2_tampered.json
# { "sha256": "f1e2d3c4...", "sha512": "...", "sha256_verified": false }
```

Note that stages after Hash (Signature, Malware, Inspect, Reputation, Policy) do not produce evidence records because the pipeline terminates after a hash mismatch. The `evidence` array will contain records only for `acquire` and `hash`.

---

## Scenario 3: FAILED — Unsigned Artifact Under Strict Policy

**Purpose:** Demonstrate that the `contractor_strict.yaml` policy rejects an artifact that has no PGP signature.

**Expected verdict:** FAILED (exit code 20)

### What Makes This Scenario Work

The unsigned fixture (`demo/fixtures/unsigned/demo_artifact.tar.gz`) has no adjacent `.asc` or `.sig` file. The `contractor_strict.yaml` policy sets `require_signature: true`, causing the policy stage to produce FAILED when the signature stage reports `missing`.

### Command

```bash
UNSIGNED="demo/fixtures/unsigned/demo_artifact.tar.gz"

./target/release/veriscan verify \
    --policy policies/contractor_strict.yaml \
    --report-json demo/out/scenario3_unsigned.json \
    --report-md  demo/out/scenario3_unsigned.md \
    "${UNSIGNED}" || true

echo "Exit code: $?"   # Expected: 20
```

### Expected Output

```
INFO  Verification pipeline started
INFO  Stage complete  stage=acquire
INFO  Stage complete  stage=hash
INFO  No signature file found  stage=signature
INFO  Stage complete  stage=signature
...
INFO  Policy evaluation complete  verdict=FAILED

╔══════════════════════════════════════╗
║  VERDICT:          FAILED            ║
╚══════════════════════════════════════╝

Reason: Signature required by policy but not present
Signature: missing
Exit code: 20
```

### Contrast: Default Policy (Permissive)

Running the same unsigned artifact with `default.yaml` (which sets `require_signature: false`) should produce VERIFIED or UNVERIFIED:

```bash
./target/release/veriscan verify \
    --policy policies/default.yaml \
    "${UNSIGNED}"
# Exit code: 0 (VERIFIED) or 10 (UNVERIFIED) — signature not required
```

---

## Scenario 4: FAILED — Malware Simulation (EICAR)

**Purpose:** Demonstrate ClamAV detection of a known malware test file (EICAR test string).

**Expected verdict:** FAILED (exit code 20) if ClamAV is installed; UNVERIFIED (exit code 10) if ClamAV is not installed.

**Note:** The EICAR test file is the industry-standard malware simulation file used to test antivirus software. It is not actually malicious; it is a string that all antivirus vendors agree to detect as `Eicar-Test-Signature`.

### Requirements

ClamAV must be installed and virus definitions must be up to date:

```bash
clamscan --version
# ClamAV 1.0.x/26955 (...)
```

### Command

```bash
MALWARE="demo/fixtures/malware_sim/eicar.com.txt"

./target/release/veriscan verify \
    --policy policies/default.yaml \
    --report-json demo/out/scenario4_malware.json \
    --report-md  demo/out/scenario4_malware.md \
    "${MALWARE}" || true

echo "Exit code: $?"   # Expected: 20 (with ClamAV), 10 (without ClamAV)
```

### Expected Output (ClamAV Installed)

```
INFO  Verification pipeline started
INFO  Stage complete  stage=acquire
INFO  Stage complete  stage=hash
INFO  Stage complete  stage=signature
WARN  detections=["Eicar-Test-Signature"]  stage=malware  "Malware detected"
INFO  Stage complete  stage=malware
INFO  Policy evaluation complete  verdict=FAILED

╔══════════════════════════════════════╗
║  VERDICT:          FAILED            ║
╚══════════════════════════════════════╝

Reason: Malware detected by scanner: Eicar-Test-Signature
Malware scan: detected
Exit code: 20
```

### Key Evidence Fields

```bash
jq '.malware_scan' demo/out/scenario4_malware.json
# {
#   "status": "detected",
#   "engine": "ClamAV",
#   "engine_version": "ClamAV 1.0.x/26955",
#   "detections": ["Eicar-Test-Signature"]
# }
```

### If ClamAV Is Not Installed

```
WARN  clamscan not found; malware scan skipped  stage=malware

╔══════════════════════════════════════╗
║  VERDICT:       UNVERIFIED           ║
╚══════════════════════════════════════╝

Reason: Malware scan required by policy but scanner unavailable
Malware scan: tool_missing
Exit code: 10
```

---

## Scenario 5: Offline Bundle Verification

**Purpose:** Demonstrate the air-gapped verification workflow using offline bundles.

The bundle structure created by `make_bundle.sh`:

```
demo/fixtures/good/bundle/
  demo_artifact.tar.gz          # The artifact
  demo_artifact.tar.gz.sha256   # SHA-256 checksum
  demo_artifact.tar.gz.sha512   # SHA-512 checksum
  demo_artifact.tar.gz.sig      # PGP detached signature
  trusted_keys/
    demo_signing_pub.asc         # Trusted public key
  bundle.manifest.json           # Signed file manifest
  bundle.manifest.sig            # PGP signature over manifest
```

### Scenario 5a: VERIFIED — Valid Bundle

```bash
./target/release/veriscan verify \
    --policy policies/airgapped.yaml \
    --offline demo/fixtures/good/bundle \
    --report-json demo/out/offline_verified.json \
    --report-md  demo/out/offline_verified.md \
    /dev/null   # source arg required but unused in --offline mode

echo "Exit code: $?"   # Expected: 0 (VERIFIED) or 10 (UNVERIFIED if no ClamAV)
```

### Scenario 5b: FAILED — Tampered Artifact in Bundle

```bash
# Create a temporary copy and tamper it
cp -r demo/fixtures/good/bundle /tmp/tampered_bundle
echo "INJECTED MALICIOUS CONTENT" >> /tmp/tampered_bundle/demo_artifact.tar.gz

./target/release/veriscan verify \
    --policy policies/airgapped.yaml \
    --offline /tmp/tampered_bundle \
    /dev/null || true

echo "Exit code: $?"   # Expected: 20 (manifest hash mismatch detected)
```

The bundle verifier detects the tampered artifact because its SHA-256 no longer matches the value in `bundle.manifest.json`.

### Scenario 5c: FAILED — Tampered Bundle Manifest

```bash
cp -r demo/fixtures/good/bundle /tmp/tampered_manifest_bundle
echo '{"injected":"malicious_entry"}' >> /tmp/tampered_manifest_bundle/bundle.manifest.json

./target/release/veriscan verify \
    --policy policies/airgapped.yaml \
    --offline /tmp/tampered_manifest_bundle \
    /dev/null || true

echo "Exit code: $?"   # Expected: 99 (manifest signature verification fails)
```

The manifest signature (`bundle.manifest.sig`) no longer matches the modified manifest JSON, so verification fails before any file content is trusted.

### Scenario 5d: FAILED — Missing Manifest Signature

```bash
cp -r demo/fixtures/good/bundle /tmp/no_sig_bundle
rm /tmp/no_sig_bundle/bundle.manifest.sig

./target/release/veriscan verify \
    --policy policies/airgapped.yaml \
    --offline /tmp/no_sig_bundle \
    /dev/null || true

echo "Exit code: $?"   # Expected: 99 (missing required signature file)
```

---

## CI/CD Integration Example

### GitHub Actions

```yaml
# .github/workflows/verify-artifact.yml
name: Verify Artifact

on:
  workflow_dispatch:
    inputs:
      artifact_path:
        description: 'Path to artifact'
        required: true
      expected_sha256:
        description: 'Expected SHA-256 checksum'
        required: true

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Install ClamAV
        run: |
          sudo apt-get update
          sudo apt-get install -y clamav
          sudo freshclam

      - name: Build veriscan
        run: cargo build --release

      - name: Verify artifact
        env:
          VT_API_KEY: ${{ secrets.VT_API_KEY }}
        run: |
          ./target/release/veriscan verify \
            --policy policies/ci_gate.yaml \
            --expected-sha256 "${{ inputs.expected_sha256 }}" \
            --trusted-keys /path/to/trusted_keys \
            --report-json verify-report.json \
            --report-md  verify-report.md \
            "${{ inputs.artifact_path }}"

      - name: Upload verification report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: verification-report
          path: |
            verify-report.json
            verify-report.md
```

### Exit Code Gate (Shell Script)

```bash
#!/bin/bash
# ci-verify-gate.sh — Fail the pipeline if verification does not pass.

set -euo pipefail

ARTIFACT="$1"
EXPECTED_SHA256="$2"

./veriscan verify \
    --policy policies/ci_gate.yaml \
    --expected-sha256 "${EXPECTED_SHA256}" \
    --trusted-keys /etc/veriscan/trusted_keys \
    --report-json "/var/log/veriscan/$(date +%Y%m%d_%H%M%S)_$(basename "${ARTIFACT}").json" \
    "${ARTIFACT}"

EXITCODE=$?

case "${EXITCODE}" in
    0)  echo "VERIFIED: artifact approved for deployment" ;;
    10) echo "UNVERIFIED: artifact requires manual review" ; exit 1 ;;
    20) echo "FAILED: artifact rejected" ; exit 1 ;;
    99) echo "TOOL ERROR: check configuration" ; exit 1 ;;
    *)  echo "UNKNOWN exit code: ${EXITCODE}" ; exit 1 ;;
esac
```

### Jenkins Pipeline (Declarative)

```groovy
pipeline {
    agent any
    environment {
        VT_API_KEY = credentials('virustotal-api-key')
    }
    stages {
        stage('Verify Artifact') {
            steps {
                sh """
                    ./veriscan verify \
                        --policy policies/ci_gate.yaml \
                        --expected-sha256 ${params.EXPECTED_SHA256} \
                        --trusted-keys ${TRUSTED_KEYS_DIR} \
                        --report-json build/verify-report.json \
                        ${params.ARTIFACT_PATH}
                """
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'build/verify-report.json'
        }
    }
}
```

---

## Docker-Based Demo

The Docker demo environment includes ClamAV with updated virus definitions, GnuPG, and veriscan pre-built.

### Build and Run

```bash
cd /path/to/veriscan

# Build the demo image (requires network for ClamAV freshclam)
docker build -t veriscan-demo -f demo/docker/Dockerfile .

# Run all demo scenarios
docker run --rm -it veriscan-demo

# Run with output directory mounted to host
mkdir -p demo/out
docker run --rm -it \
    -v "$(pwd)/demo/out:/demo/out" \
    veriscan-demo

# Run with VirusTotal API key
docker run --rm -it \
    -e VT_API_KEY="${VT_API_KEY}" \
    -v "$(pwd)/demo/out:/demo/out" \
    veriscan-demo
```

### Docker Demo Entrypoint

The container entrypoint (`demo/docker/entrypoint.sh`) runs:
1. `make_bundle.sh` — generates all demo fixtures with fresh GPG keys.
2. `run_online_demo.sh` — runs Scenarios 1–4.
3. `run_offline_demo.sh` — runs Scenarios 5a–5d.
4. `generate_reports.sh` — formats and summarizes all report outputs.

### Docker Compose

```bash
# Run with Docker Compose
docker compose -f demo/docker/docker-compose.yml up

# View output
cat demo/out/scenario1_verified.md
jq '.verdict' demo/out/scenario1_verified.json
```

---

## Expected Outputs and Verdicts Summary

| Scenario | Policy | Artifact State | Expected Verdict | Exit Code |
|---|---|---|---|---|
| 1: Valid artifact | default | Signed, hash matches | VERIFIED | 0 |
| 2: Tampered artifact | default | Hash mismatch | FAILED | 20 |
| 3: Unsigned (strict) | contractor_strict | No signature | FAILED | 20 |
| 3: Unsigned (default) | default | No signature | VERIFIED or UNVERIFIED | 0 or 10 |
| 4: EICAR (ClamAV present) | default | Malware detected | FAILED | 20 |
| 4: EICAR (no ClamAV) | default | Scanner unavailable | UNVERIFIED | 10 |
| 5a: Valid bundle | airgapped | Bundle intact | VERIFIED or UNVERIFIED | 0 or 10 |
| 5b: Tampered artifact | airgapped | File hash mismatch in manifest | FAILED | 20 |
| 5c: Tampered manifest | airgapped | Manifest sig invalid | FAILED | 99 |
| 5d: Missing manifest sig | airgapped | Manifest sig missing | FAILED | 99 |

Notes:
- Scenarios producing UNVERIFIED (exit 10) indicate incomplete verification, typically due to ClamAV or VirusTotal being unavailable. Whether UNVERIFIED is acceptable depends on the deployment policy.
- Scenarios 5c and 5d produce exit code 99 (tool error) because bundle verification failure is treated as a pipeline error rather than a policy verdict. The artifact is never trusted when the bundle manifest signature fails.
- Exit code 10 may become 0 (VERIFIED) if `malware_failure_is_fatal: false` and `reputation_required: false` are set in the policy, which is the default configuration.

---

## Troubleshooting

### "clamscan not found" / UNVERIFIED on Scenario 4

ClamAV is not installed or not on the default search paths. Install ClamAV and run `freshclam` to update definitions. Alternatively, set `malware_tool_path: "/absolute/path/to/clamscan"` in the policy file.

### "No trusted public keys loaded" / Signature Invalid

The `--trusted-keys` directory does not contain any `.asc`, `.pub`, `.pgp`, or `.gpg` files, or the files failed to parse. Run `make_bundle.sh` to regenerate demo keys.

### "Policy requires checksums but no sha256 checksum found"

The `require_checksums: true` policy flag is set but no expected checksum was provided and no adjacent `.sha256` file was found. Either provide `--expected-sha256` or create a `<artifact>.sha256` file.

### "Network access denied by policy"

The `airgapped.yaml` policy (`allow_network: false`) rejected a URL source or a reputation lookup. Use `--offline` mode with a bundle, or switch to a policy that permits network access.

### Exit Code 99 (Tool Error)

Indicates a configuration or I/O error, not a verification verdict. Check:
- Policy file exists and is valid YAML (`veriscan policy-validate`).
- Artifact path exists and is readable.
- Report output directory exists.
- Bundle directory has the expected structure.
