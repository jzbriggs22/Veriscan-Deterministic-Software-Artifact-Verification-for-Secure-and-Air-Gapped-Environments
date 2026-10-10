#!/usr/bin/env bash
# run_offline_demo.sh — Demonstrates offline (air-gapped) verification.
#
# Scenarios:
#   1. VERIFIED:  Valid offline bundle
#   2. FAILED:    Tampered artifact in bundle
#   3. FAILED:    Tampered bundle manifest
#   4. FAILED:    Missing manifest signature

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES_DIR="${DEMO_DIR}/fixtures"
OUT_DIR="${DEMO_DIR}/out"
POLICIES_DIR="/policies"

[ -d "${POLICIES_DIR}" ] || POLICIES_DIR="${DEMO_DIR}/../policies"

mkdir -p "${OUT_DIR}"

# Ensure fixtures (and the pinned demo policy) exist.
PINNED_POLICY="${OUT_DIR}/airgapped_pinned.yaml"
if [ ! -d "${FIXTURES_DIR}/good/bundle" ] || [ ! -f "${PINNED_POLICY}" ]; then
    echo "[offline-demo] Bundle or pinned policy not found; running make_bundle.sh..."
    bash "${SCRIPT_DIR}/make_bundle.sh"
fi

VERISCAN="veriscan"
command -v veriscan &>/dev/null || VERISCAN="${DEMO_DIR}/../target/release/veriscan"

separator() {
    echo ""
    echo "──────────────────────────────────────────────────────────"
    echo " $1"
    echo "──────────────────────────────────────────────────────────"
}

BUNDLE_DIR="${FIXTURES_DIR}/good/bundle"

# ── Scenario 1: VERIFIED — Valid offline bundle ───────────────────────────
# Uses the pinned policy (demo signer fingerprint in allow_signers). With
# ClamAV installed the scenario must reach a full VERIFIED (exit 0); without
# a scanner the air-gapped policy fails closed on the missing scanner alone
# (exit 20) — the signature and checksum checks still pass.

separator "Offline Scenario 1: VERIFIED — Valid offline bundle"

"${VERISCAN}" verify \
    --policy "${PINNED_POLICY}" \
    --offline "${BUNDLE_DIR}" \
    --report-json "${OUT_DIR}/offline_scenario1_verified.json" \
    --report-md  "${OUT_DIR}/offline_scenario1_verified.md" \
    /dev/null && EXITCODE=0 || EXITCODE=$?   # Source arg unused in offline mode
echo "Exit code: ${EXITCODE}"
if command -v clamscan &>/dev/null; then
    [ "${EXITCODE}" -eq 0 ] \
        && echo "✅ PASS: Full VERIFIED — pinned signer accepted, checksums match, malware scan clean" \
        || echo "❌ FAIL: Expected exit 0 (ClamAV is installed), got ${EXITCODE}"
else
    if [ "${EXITCODE}" -eq 20 ] \
        && grep -q "scanner unavailable" "${OUT_DIR}/offline_scenario1_verified.json"; then
        echo "✅ PASS: Signer accepted and checksums match; fail-closed only on the missing malware scanner (install ClamAV for exit 0)"
    else
        echo "❌ FAIL: Expected exit 20 due to missing scanner, got ${EXITCODE}"
    fi
fi

# ── Scenario 2: FAILED — Tampered artifact in bundle ─────────────────────

separator "Offline Scenario 2: FAILED — Tampered artifact in bundle"

# Create a copy of the bundle with a tampered artifact.
TAMPERED_BUNDLE="${OUT_DIR}/tampered_bundle"
rm -rf "${TAMPERED_BUNDLE}"
cp -r "${BUNDLE_DIR}" "${TAMPERED_BUNDLE}"

# Tamper the artifact (add bytes to change its hash).
echo "TAMPERED" >> "${TAMPERED_BUNDLE}/demo_artifact.tar.gz"

"${VERISCAN}" verify \
    --policy "${POLICIES_DIR}/airgapped.yaml" \
    --offline "${TAMPERED_BUNDLE}" \
    --report-json "${OUT_DIR}/offline_scenario2_tampered.json" \
    --report-md  "${OUT_DIR}/offline_scenario2_tampered.md" \
    /dev/null && EXITCODE=0 || EXITCODE=$?
echo "Exit code: ${EXITCODE}"
[ "${EXITCODE}" -eq 99 ] \
    && echo "✅ PASS: Tampered artifact detected (exit 99: bundle integrity error)" \
    || echo "❌ FAIL: Expected exit 99, got ${EXITCODE}"

# ── Scenario 3: FAILED — Tampered manifest ───────────────────────────────

separator "Offline Scenario 3: FAILED — Tampered bundle manifest"

TAMPERED_MANIFEST_BUNDLE="${OUT_DIR}/tampered_manifest_bundle"
rm -rf "${TAMPERED_MANIFEST_BUNDLE}"
cp -r "${BUNDLE_DIR}" "${TAMPERED_MANIFEST_BUNDLE}"

# Tamper the manifest JSON (the signature will no longer match).
echo '{"injected": "tampered entry"}' >> "${TAMPERED_MANIFEST_BUNDLE}/bundle.manifest.json"

"${VERISCAN}" verify \
    --policy "${POLICIES_DIR}/airgapped.yaml" \
    --offline "${TAMPERED_MANIFEST_BUNDLE}" \
    --report-json "${OUT_DIR}/offline_scenario3_tampered_manifest.json" \
    --report-md  "${OUT_DIR}/offline_scenario3_tampered_manifest.md" \
    /dev/null && EXITCODE=0 || EXITCODE=$?
echo "Exit code: ${EXITCODE}"
[ "${EXITCODE}" -eq 99 ] \
    && echo "✅ PASS: Tampered manifest detected (exit 99: bundle integrity error)" \
    || echo "❌ FAIL: Expected exit 99, got ${EXITCODE}"

# ── Scenario 4: FAILED — Missing manifest signature ──────────────────────

separator "Offline Scenario 4: FAILED — Missing manifest signature"

NO_SIG_BUNDLE="${OUT_DIR}/no_sig_bundle"
rm -rf "${NO_SIG_BUNDLE}"
cp -r "${BUNDLE_DIR}" "${NO_SIG_BUNDLE}"
rm -f "${NO_SIG_BUNDLE}/bundle.manifest.sig"

"${VERISCAN}" verify \
    --policy "${POLICIES_DIR}/airgapped.yaml" \
    --offline "${NO_SIG_BUNDLE}" \
    --report-json "${OUT_DIR}/offline_scenario4_no_sig.json" \
    --report-md  "${OUT_DIR}/offline_scenario4_no_sig.md" \
    /dev/null && EXITCODE=0 || EXITCODE=$?
echo "Exit code: ${EXITCODE}"
[ "${EXITCODE}" -eq 99 ] \
    && echo "✅ PASS: Missing signature detected (exit 99: bundle integrity error)" \
    || echo "❌ FAIL: Expected exit 99, got ${EXITCODE}"

separator "Offline demo complete"
echo "Reports written to: ${OUT_DIR}/"
ls -la "${OUT_DIR}/"
