#!/usr/bin/env bash
# Veriscan Demo Container Entrypoint
# ====================================
# Runs the full demo sequence and generates reports.
# Exit code reflects the last scenario's result.

set -euo pipefail

DEMO_DIR="/demo"
OUT_DIR="${DEMO_DIR}/out"
SCRIPTS_DIR="${DEMO_DIR}/scripts"
KEYS_DIR="${DEMO_DIR}/keys"

mkdir -p "${OUT_DIR}" "${KEYS_DIR}"

echo "======================================================"
echo " Veriscan Demo Container"
echo " $(veriscan --version 2>&1 || echo 'veriscan (unknown version)')"
echo "======================================================"
echo ""

# Generate demo keys if not already present.
if [ ! -f "${KEYS_DIR}/demo_signing_pub.asc" ]; then
    echo "[*] Generating demo GPG key pair..."
    "${SCRIPTS_DIR}/make_bundle.sh" --keys-only
fi

echo ""
echo "[1/5] Running online demo (signed + hashed artifact)..."
bash "${SCRIPTS_DIR}/run_online_demo.sh" || true

echo ""
echo "[2/5] Running offline bundle demo..."
bash "${SCRIPTS_DIR}/run_offline_demo.sh" || true

echo ""
echo "[3/5] Running CI gate validation..."
bash "${SCRIPTS_DIR}/validate_ci_gate.sh" || true

echo ""
echo "[4/5] Generating reports..."
bash "${SCRIPTS_DIR}/generate_reports.sh" || true

echo ""
echo "======================================================"
echo " Demo complete. Reports in ${OUT_DIR}/"
echo "======================================================"
ls -la "${OUT_DIR}/" || true

# If called with arguments, pass through to a shell.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi
