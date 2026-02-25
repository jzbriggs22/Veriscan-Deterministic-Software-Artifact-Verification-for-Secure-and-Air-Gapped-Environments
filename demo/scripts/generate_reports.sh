#!/usr/bin/env bash
# generate_reports.sh — Generate JSON and Markdown reports for all demo scenarios.
#
# This script summarises all reports in demo/out/ into a unified index.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${DEMO_DIR}/out"

mkdir -p "${OUT_DIR}"

VERISCAN="veriscan"
command -v veriscan &>/dev/null || VERISCAN="${DEMO_DIR}/../../target/release/veriscan"

echo "======================================================"
echo " Veriscan Report Generation"
echo "======================================================"
echo ""

# Print JSON schema description.
echo "[reports] Report schema:"
"${VERISCAN}" report-schema

echo ""
echo "[reports] Existing reports in ${OUT_DIR}/:"
ls -la "${OUT_DIR}/" 2>/dev/null || echo "(none yet)"

# Build an index of all JSON reports.
INDEX_FILE="${OUT_DIR}/report_index.json"
echo '{"reports": [' > "${INDEX_FILE}"
FIRST=true
for f in "${OUT_DIR}"/*.json; do
    [ -f "${f}" ] || continue
    [[ "${f}" == *"report_index"* ]] && continue
    if [ "${FIRST}" = "false" ]; then
        echo ',' >> "${INDEX_FILE}"
    fi
    FIRST=false

    # Extract key fields.
    VERDICT=$(jq -r '.verdict.status // "unknown"' "${f}" 2>/dev/null || echo "unknown")
    RUN_ID=$(jq -r '.run_id // "unknown"' "${f}" 2>/dev/null || echo "unknown")
    TIMESTAMP=$(jq -r '.timestamp // "unknown"' "${f}" 2>/dev/null || echo "unknown")
    ARTIFACT=$(jq -r '.artifact.filename // "unknown"' "${f}" 2>/dev/null || echo "unknown")
    EXIT_CODE=$(jq -r '.verdict.exit_code // -1' "${f}" 2>/dev/null || echo "-1")

    echo "  {" >> "${INDEX_FILE}"
    echo "    \"report_file\": \"$(basename "${f}")\"," >> "${INDEX_FILE}"
    echo "    \"run_id\": \"${RUN_ID}\"," >> "${INDEX_FILE}"
    echo "    \"timestamp\": \"${TIMESTAMP}\"," >> "${INDEX_FILE}"
    echo "    \"artifact\": \"${ARTIFACT}\"," >> "${INDEX_FILE}"
    echo "    \"verdict\": \"${VERDICT}\"," >> "${INDEX_FILE}"
    echo "    \"exit_code\": ${EXIT_CODE}" >> "${INDEX_FILE}"
    printf '  }' >> "${INDEX_FILE}"
done
echo "" >> "${INDEX_FILE}"
echo ']}' >> "${INDEX_FILE}"

echo ""
echo "[reports] Report index written to: ${INDEX_FILE}"
echo ""
echo "[reports] Summary:"
jq -r '.reports[] | "  \(.verdict)\t\(.artifact)\t\(.report_file)"' "${INDEX_FILE}" \
    2>/dev/null || echo "  (no reports)"

echo ""
echo "[reports] Done."
