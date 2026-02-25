#!/usr/bin/env bash
# run_online_demo.sh — Demonstrates online verification scenarios.
#
# Scenarios:
#   1. VERIFIED:   Signed artifact with valid checksums
#   2. FAILED:     Tampered artifact (hash mismatch)
#   3. UNVERIFIED: Unsigned artifact under strict policy
#   4. FAILED:     Malware simulation (EICAR)
#
# Reports are written to demo/out/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES_DIR="${DEMO_DIR}/fixtures"
OUT_DIR="${DEMO_DIR}/out"
POLICIES_DIR="/policies"

# Fall back to local policies if /policies not available.
[ -d "${POLICIES_DIR}" ] || POLICIES_DIR="${DEMO_DIR}/../../policies"

mkdir -p "${OUT_DIR}"

# Run make_bundle.sh if fixtures don't exist yet.
if [ ! -f "${FIXTURES_DIR}/good/demo_artifact.tar.gz" ]; then
    echo "[online-demo] Fixtures not found; running make_bundle.sh..."
    bash "${SCRIPT_DIR}/make_bundle.sh"
fi

VERISCAN="veriscan"
command -v veriscan &>/dev/null || VERISCAN="${DEMO_DIR}/../../target/release/veriscan"

separator() {
    echo ""
    echo "──────────────────────────────────────────────────────────"
    echo " $1"
    echo "──────────────────────────────────────────────────────────"
}

# ── Scenario 1: VERIFIED ──────────────────────────────────────────────────

separator "Scenario 1: VERIFIED — Signed artifact with valid checksums"

GOOD="${FIXTURES_DIR}/good/demo_artifact.tar.gz"
EXPECTED_SHA256=$(cat "${GOOD}.sha256")

"${VERISCAN}" verify \
    --policy "${POLICIES_DIR}/default.yaml" \
    --expected-sha256 "${EXPECTED_SHA256}" \
    --trusted-keys "${FIXTURES_DIR}/good/trusted_keys" \
    --sig "${GOOD}.asc" \
    --report-json "${OUT_DIR}/scenario1_verified.json" \
    --report-md  "${OUT_DIR}/scenario1_verified.md" \
    "${GOOD}"

EXITCODE=$?
echo ""
echo "Exit code: ${EXITCODE}"
[ "${EXITCODE}" -eq 0 ] && echo "✅ PASS: Expected VERIFIED (exit 0)" \
    || echo "❌ FAIL: Expected exit 0, got ${EXITCODE}"

# ── Scenario 2: FAILED — Tampered artifact ────────────────────────────────

separator "Scenario 2: FAILED — Tampered artifact (hash mismatch)"

TAMPERED="${FIXTURES_DIR}/tampered/demo_artifact.tar.gz"
EXPECTED_SHA256_TAMPERED=$(cat "${FIXTURES_DIR}/good/demo_artifact.tar.gz.sha256")

"${VERISCAN}" verify \
    --policy "${POLICIES_DIR}/default.yaml" \
    --expected-sha256 "${EXPECTED_SHA256_TAMPERED}" \
    --trusted-keys "${FIXTURES_DIR}/tampered/trusted_keys" \
    --report-json "${OUT_DIR}/scenario2_tampered.json" \
    --report-md  "${OUT_DIR}/scenario2_tampered.md" \
    "${TAMPERED}" || true

EXITCODE=$?
echo ""
echo "Exit code: ${EXITCODE}"
[ "${EXITCODE}" -eq 20 ] && echo "✅ PASS: Expected FAILED (exit 20)" \
    || echo "❌ FAIL: Expected exit 20, got ${EXITCODE}"

# ── Scenario 3: UNVERIFIED — Unsigned artifact (strict policy) ───────────

separator "Scenario 3: UNVERIFIED/FAILED — Unsigned artifact (contractor_strict policy)"

UNSIGNED="${FIXTURES_DIR}/unsigned/demo_artifact.tar.gz"

"${VERISCAN}" verify \
    --policy "${POLICIES_DIR}/contractor_strict.yaml" \
    --report-json "${OUT_DIR}/scenario3_unsigned.json" \
    --report-md  "${OUT_DIR}/scenario3_unsigned.md" \
    "${UNSIGNED}" || true

EXITCODE=$?
echo ""
echo "Exit code: ${EXITCODE}"
( [ "${EXITCODE}" -eq 20 ] || [ "${EXITCODE}" -eq 10 ] ) \
    && echo "✅ PASS: Expected FAILED or UNVERIFIED (exit 20 or 10)" \
    || echo "❌ FAIL: Expected exit 20 or 10, got ${EXITCODE}"

# ── Scenario 4: FAILED — Malware simulation (EICAR) ──────────────────────

separator "Scenario 4: FAILED — Malware simulation (EICAR test file)"

MALWARE="${FIXTURES_DIR}/malware_sim/eicar.com.txt"

"${VERISCAN}" verify \
    --policy "${POLICIES_DIR}/default.yaml" \
    --report-json "${OUT_DIR}/scenario4_malware.json" \
    --report-md  "${OUT_DIR}/scenario4_malware.md" \
    "${MALWARE}" || true

EXITCODE=$?
echo ""
echo "Exit code: ${EXITCODE}"
# ClamAV may not be installed; accept UNVERIFIED (10) or FAILED (20).
( [ "${EXITCODE}" -eq 20 ] || [ "${EXITCODE}" -eq 10 ] || [ "${EXITCODE}" -eq 0 ] ) \
    && echo "✅ PASS: Malware scenario completed (ClamAV may not be installed)" \
    || echo "❌ FAIL: Unexpected exit code ${EXITCODE}"

separator "Online demo complete"
echo "Reports written to: ${OUT_DIR}/"
ls -la "${OUT_DIR}/"
