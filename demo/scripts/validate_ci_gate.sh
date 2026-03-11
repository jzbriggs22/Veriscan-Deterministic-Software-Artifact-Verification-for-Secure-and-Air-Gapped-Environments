#!/usr/bin/env bash
# validate_ci_gate.sh — Demonstrates CI/CD gating with veriscan.
#
# Shows how to integrate veriscan into CI pipelines with proper exit codes.
# Mimics a pipeline gate that:
#   - Accepts verified artifacts (exit 0)
#   - Warns on unverified (exit 10)
#   - Blocks on failed (exit 20)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES_DIR="${DEMO_DIR}/fixtures"
OUT_DIR="${DEMO_DIR}/out"
POLICIES_DIR="/policies"

[ -d "${POLICIES_DIR}" ] || POLICIES_DIR="${DEMO_DIR}/../../policies"

mkdir -p "${OUT_DIR}"

# Ensure fixtures exist.
if [ ! -f "${FIXTURES_DIR}/good/demo_artifact.tar.gz" ]; then
    bash "${SCRIPT_DIR}/make_bundle.sh"
fi

VERISCAN="veriscan"
command -v veriscan &>/dev/null || VERISCAN="${DEMO_DIR}/../../target/release/veriscan"

echo "======================================================"
echo " CI Gate Validation Demo"
echo " Policy: ci_gate.yaml"
echo "======================================================"
echo ""

# Function: check artifact with CI gate policy.
gate_check() {
    local artifact="$1"
    local description="$2"
    local report_base="$3"
    local extra_args=("${@:4}")

    echo "── ${description}"
    echo "   Artifact: $(basename "${artifact}")"

    local exitcode
    "${VERISCAN}" verify \
        --policy "${POLICIES_DIR}/ci_gate.yaml" \
        --report-json "${OUT_DIR}/${report_base}.json" \
        --report-md  "${OUT_DIR}/${report_base}.md" \
        "${extra_args[@]}" \
        "${artifact}" && exitcode=0 || exitcode=$?
    echo -n "   Exit code: ${exitcode} → "

    case "${exitcode}" in
        0)  echo "✅ VERIFIED  — CI pipeline continues" ;;
        10) echo "⚠️  UNVERIFIED — CI pipeline should warn" ;;
        20) echo "❌ FAILED    — CI pipeline BLOCKED" ;;
        99) echo "🔴 TOOL ERROR — investigate" ;;
        *)  echo "❓ UNKNOWN code ${exitcode}" ;;
    esac
    echo ""
    return "${exitcode}" || true
}

# Test 1: Good artifact (with sig + checksums).
GOOD="${FIXTURES_DIR}/good/demo_artifact.tar.gz"
EXPECTED_SHA256=$(cat "${GOOD}.sha256" 2>/dev/null || echo "")

gate_check \
    "${GOOD}" \
    "Good artifact (signed + checksums)" \
    "ci_gate_good" \
    --expected-sha256 "${EXPECTED_SHA256}" \
    --trusted-keys "${FIXTURES_DIR}/good/trusted_keys" \
    --sig "${GOOD}.asc" \
    || true

# Test 2: Tampered artifact.
TAMPERED="${FIXTURES_DIR}/tampered/demo_artifact.tar.gz"
EXPECTED_SHA256_ORIG=$(cat "${FIXTURES_DIR}/good/demo_artifact.tar.gz.sha256" 2>/dev/null || echo "")

gate_check \
    "${TAMPERED}" \
    "Tampered artifact (hash mismatch)" \
    "ci_gate_tampered" \
    --expected-sha256 "${EXPECTED_SHA256_ORIG}" \
    || true

# Test 3: Unsigned artifact.
gate_check \
    "${FIXTURES_DIR}/unsigned/demo_artifact.tar.gz" \
    "Unsigned artifact" \
    "ci_gate_unsigned" \
    || true

# Test 4: Validate all policies.
echo "── Policy validation"
for policy_file in "${POLICIES_DIR}"/*.yaml; do
    "${VERISCAN}" policy-validate "${policy_file}" 2>&1 \
        && echo "   ✅ $(basename "${policy_file}")" \
        || echo "   ❌ $(basename "${policy_file}") FAILED validation"
done

echo ""
echo "======================================================"
echo " CI Gate demo complete. Reports in ${OUT_DIR}/"
echo "======================================================"
echo ""
echo "Integration example (bash):"
echo '  veriscan verify --policy ci_gate.yaml artifact.tar.gz'
echo '  exit_code=$?'
echo '  if [ $exit_code -eq 0 ]; then'
echo '    echo "CI: Artifact verified — continuing pipeline"'
echo '  elif [ $exit_code -eq 10 ]; then'
echo '    echo "CI: Artifact unverified — WARNING (check policy)"'
echo '    # Optionally block: exit 1'
echo '  else'
echo '    echo "CI: Artifact FAILED — BLOCKING pipeline"'
echo '    exit 1'
echo '  fi'
