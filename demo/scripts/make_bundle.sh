#!/usr/bin/env bash
# make_bundle.sh — Create demo fixtures and offline verification bundle.
#
# Usage:
#   ./make_bundle.sh          — full setup: keys + fixtures + bundle
#   ./make_bundle.sh --keys-only  — only generate demo key pair
#
# Produces:
#   demo/keys/demo_signing_pub.asc   — armored public key
#   demo/keys/demo_signing_sec.asc   — armored SECRET key (DEMO ONLY)
#   demo/fixtures/good/              — signed artifact + checksums
#   demo/fixtures/tampered/          — modified artifact (hash mismatch)
#   demo/fixtures/unsigned/          — artifact without signature
#   demo/fixtures/malware_sim/       — EICAR test file
#   demo/fixtures/good/bundle/       — offline verification bundle

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_DIR="${DEMO_DIR}/keys"
FIXTURES_DIR="${DEMO_DIR}/fixtures"
OUT_DIR="${DEMO_DIR}/out"

KEYS_ONLY="${1:-}"

mkdir -p "${KEYS_DIR}" "${OUT_DIR}"
mkdir -p "${FIXTURES_DIR}/good" "${FIXTURES_DIR}/tampered" \
    "${FIXTURES_DIR}/unsigned" "${FIXTURES_DIR}/malware_sim"

# ── Key generation ────────────────────────────────────────────────────────

echo "[make_bundle] Checking for demo keys..."

if [ ! -f "${KEYS_DIR}/demo_signing_pub.asc" ] || [ ! -f "${KEYS_DIR}/demo_signing_sec.asc" ]; then
    echo "[make_bundle] Generating demo Ed25519 key pair..."

    # Use a temporary GPG home to avoid polluting the user's keyring.
    GPG_TMPDIR="$(mktemp -d)"
    chmod 700 "${GPG_TMPDIR}"
    trap "rm -rf '${GPG_TMPDIR}'" EXIT

    # Generate Ed25519 key (no passphrase for demo automation).
    gpg --homedir "${GPG_TMPDIR}" --batch --gen-key <<EOF
%no-protection
Key-Type: EdDSA
Key-Curve: Ed25519
Key-Usage: sign
Name-Real: Veriscan Demo Signer
Name-Email: demo-signer@veriscan.example
Expire-Date: 2y
%commit
EOF

    # Export public key.
    gpg --homedir "${GPG_TMPDIR}" \
        --armor \
        --export "demo-signer@veriscan.example" \
        > "${KEYS_DIR}/demo_signing_pub.asc"

    # Export secret key (DEMO ONLY — never use in production).
    gpg --homedir "${GPG_TMPDIR}" \
        --armor \
        --export-secret-keys "demo-signer@veriscan.example" \
        > "${KEYS_DIR}/demo_signing_sec.asc"

    echo "[make_bundle] Demo keys generated."
    echo "  Public:  ${KEYS_DIR}/demo_signing_pub.asc"
    echo "  SECRET:  ${KEYS_DIR}/demo_signing_sec.asc"
    echo "  WARNING: These keys are for DEMO ONLY. Do not use in production."
else
    echo "[make_bundle] Demo keys already exist."
fi

# Get the key fingerprint.
GPG_TMPDIR2="$(mktemp -d)"
chmod 700 "${GPG_TMPDIR2}"
trap "rm -rf '${GPG_TMPDIR2}'" EXIT

gpg --homedir "${GPG_TMPDIR2}" --import "${KEYS_DIR}/demo_signing_pub.asc" 2>/dev/null
gpg --homedir "${GPG_TMPDIR2}" --import "${KEYS_DIR}/demo_signing_sec.asc" 2>/dev/null

KEY_FP=$(gpg --homedir "${GPG_TMPDIR2}" \
    --with-colons --fingerprint "demo-signer@veriscan.example" 2>/dev/null \
    | grep "^fpr" | head -1 | cut -d: -f10)
echo "[make_bundle] Key fingerprint: ${KEY_FP}"

# ── Pinned air-gapped policy ──────────────────────────────────────────────
# Derive a demo policy from policies/airgapped.yaml with the demo signer's
# fingerprint in allow_signers. The stock policy ships with an empty
# allowlist (fail-closed), so scenario 1 of the offline demo can only reach
# a full VERIFIED verdict with this pinned variant (plus ClamAV installed).

POLICIES_DIR="/policies"
[ -d "${POLICIES_DIR}" ] || POLICIES_DIR="${DEMO_DIR}/../policies"
PINNED_POLICY="${OUT_DIR}/airgapped_pinned.yaml"

sed "s|^allow_signers: \[\]$|allow_signers:\n  - \"${KEY_FP}\"|" \
    "${POLICIES_DIR}/airgapped.yaml" > "${PINNED_POLICY}"
grep -q "${KEY_FP}" "${PINNED_POLICY}" || {
    echo "[make_bundle] ERROR: failed to pin fingerprint into ${PINNED_POLICY}" >&2
    exit 1
}
echo "[make_bundle] Pinned air-gapped policy written: ${PINNED_POLICY}"

[ "${KEYS_ONLY}" = "--keys-only" ] && exit 0

# ── Fixture: good artifact ────────────────────────────────────────────────

echo ""
echo "[make_bundle] Creating 'good' fixture (signed + checksums)..."

GOOD_ARTIFACT="${FIXTURES_DIR}/good/demo_artifact.tar.gz"

# Create a demo tarball.
mkdir -p /tmp/demo_src
echo "This is a demo artifact for veriscan testing." > /tmp/demo_src/README.txt
echo "Version: 1.0.0" >> /tmp/demo_src/README.txt
echo "Build date: $(date -u '+%Y-%m-%d')" >> /tmp/demo_src/README.txt
tar -czf "${GOOD_ARTIFACT}" -C /tmp/demo_src .

# Compute checksums.
sha256sum "${GOOD_ARTIFACT}" | awk '{print $1}' > "${GOOD_ARTIFACT}.sha256"
sha512sum "${GOOD_ARTIFACT}" | awk '{print $1}' > "${GOOD_ARTIFACT}.sha512"

# Create detached signature.
gpg --homedir "${GPG_TMPDIR2}" \
    --local-user "demo-signer@veriscan.example" \
    --detach-sign \
    --armor \
    --output "${GOOD_ARTIFACT}.asc" \
    "${GOOD_ARTIFACT}"

# Copy public key to trusted_keys/ adjacent to artifact.
mkdir -p "${FIXTURES_DIR}/good/trusted_keys"
cp "${KEYS_DIR}/demo_signing_pub.asc" "${FIXTURES_DIR}/good/trusted_keys/"

echo "[make_bundle] Good fixture created:"
echo "  Artifact: ${GOOD_ARTIFACT}"
echo "  SHA-256:  $(cat "${GOOD_ARTIFACT}.sha256")"
echo "  Signature: ${GOOD_ARTIFACT}.asc"

# ── Fixture: tampered artifact ─────────────────────────────────────────────

echo ""
echo "[make_bundle] Creating 'tampered' fixture (hash mismatch)..."

TAMPERED_ARTIFACT="${FIXTURES_DIR}/tampered/demo_artifact.tar.gz"
cp "${GOOD_ARTIFACT}" "${TAMPERED_ARTIFACT}"
cp "${GOOD_ARTIFACT}.sha256" "${TAMPERED_ARTIFACT}.sha256"
cp "${GOOD_ARTIFACT}.asc" "${TAMPERED_ARTIFACT}.asc"
mkdir -p "${FIXTURES_DIR}/tampered/trusted_keys"
cp "${KEYS_DIR}/demo_signing_pub.asc" "${FIXTURES_DIR}/tampered/trusted_keys/"

# Tamper the artifact AFTER copying the valid signature.
echo "TAMPERED CONTENT INJECTED" >> "${TAMPERED_ARTIFACT}"

echo "[make_bundle] Tampered fixture created (hash will mismatch signature)."
echo "  Artifact: ${TAMPERED_ARTIFACT}"

# ── Fixture: unsigned artifact ─────────────────────────────────────────────

echo ""
echo "[make_bundle] Creating 'unsigned' fixture (no signature)..."

UNSIGNED_ARTIFACT="${FIXTURES_DIR}/unsigned/demo_artifact.tar.gz"
cp "${GOOD_ARTIFACT}" "${UNSIGNED_ARTIFACT}"
sha256sum "${UNSIGNED_ARTIFACT}" | awk '{print $1}' > "${UNSIGNED_ARTIFACT}.sha256"
# No .asc or .sig file.

echo "[make_bundle] Unsigned fixture created."

# ── Fixture: malware simulation (EICAR) ───────────────────────────────────

echo ""
echo "[make_bundle] Creating malware simulation fixture (EICAR test string)..."

MALWARE_ARTIFACT="${FIXTURES_DIR}/malware_sim/eicar.com.txt"
# EICAR test string — safe, universally recognized AV test file.
# This is the standard EICAR test string, which ALL AV engines detect.
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    > "${MALWARE_ARTIFACT}"

echo "[make_bundle] EICAR test file created: ${MALWARE_ARTIFACT}"
echo "  (This file will be detected by ClamAV as 'Eicar-Signature')"

# ── Offline bundle ────────────────────────────────────────────────────────

echo ""
echo "[make_bundle] Creating offline verification bundle..."

BUNDLE_DIR="${FIXTURES_DIR}/good/bundle"
rm -rf "${BUNDLE_DIR}"

veriscan bundle create \
    --artifact "${GOOD_ARTIFACT}" \
    --keys "${KEYS_DIR}" \
    --signing-key "${KEYS_DIR}/demo_signing_sec.asc" \
    --out "${BUNDLE_DIR}" \
    2>&1 || {
    echo "[make_bundle] veriscan bundle create not available; creating bundle manually..."
    mkdir -p "${BUNDLE_DIR}/trusted_keys"
    cp "${GOOD_ARTIFACT}" "${BUNDLE_DIR}/demo_artifact.tar.gz"
    cp "${GOOD_ARTIFACT}.sha256" "${BUNDLE_DIR}/demo_artifact.tar.gz.sha256"
    cp "${GOOD_ARTIFACT}.sha512" "${BUNDLE_DIR}/demo_artifact.tar.gz.sha512" || true
    cp "${GOOD_ARTIFACT}.asc" "${BUNDLE_DIR}/demo_artifact.tar.gz.sig" || true
    cp "${KEYS_DIR}/demo_signing_pub.asc" "${BUNDLE_DIR}/trusted_keys/"

    # Build manifest JSON.
    ARTIFACT_SHA256=$(sha256sum "${BUNDLE_DIR}/demo_artifact.tar.gz" | awk '{print $1}')
    SIG_SHA256=$(sha256sum "${BUNDLE_DIR}/demo_artifact.tar.gz.sig" | awk '{print $1}' 2>/dev/null || echo "")
    KEY_SHA256=$(sha256sum "${BUNDLE_DIR}/trusted_keys/demo_signing_pub.asc" | awk '{print $1}')

    cat > "${BUNDLE_DIR}/bundle.manifest.json" <<MANIFEST
{
  "schema_version": "1.0",
  "created_at": "$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')",
  "artifact_filename": "demo_artifact.tar.gz",
  "files": [
    {"path": "demo_artifact.tar.gz", "sha256": "${ARTIFACT_SHA256}"},
    {"path": "trusted_keys/demo_signing_pub.asc", "sha256": "${KEY_SHA256}"}
  ]
}
MANIFEST

    # Sign the manifest.
    gpg --homedir "${GPG_TMPDIR2}" \
        --local-user "demo-signer@veriscan.example" \
        --detach-sign \
        --armor \
        --output "${BUNDLE_DIR}/bundle.manifest.sig" \
        "${BUNDLE_DIR}/bundle.manifest.json"
}

echo "[make_bundle] Bundle created at: ${BUNDLE_DIR}"
echo ""
echo "[make_bundle] All fixtures ready."
echo ""
ls -la "${FIXTURES_DIR}/good/"
