#!/bin/bash
set -euo pipefail

OUTPUT_DIR="output"
DRIFT_FILE="${OUTPUT_DIR}/pci_dss_drifts.json"
RESULT_FILE="${OUTPUT_DIR}/pci_dss_results.json"

mkdir -p "$OUTPUT_DIR"

echo "[*] Running PCI DSS validation with OPA..."

# Collect violations only (as before)
violations=$(opa eval \
  --input output/azure.json \
  --data policy/azure/pci_dss.rego \
  "data.azure.pci_dss.deny" \
  -f json)

echo "$violations" | jq '.' > "$DRIFT_FILE"

# Collect both passes and fails
results=$(opa eval \
  --input output/azure.json \
  --data policy/azure/pci_dss.rego \
  '{"deny": data.azure.pci_dss.deny, "pass": data.azure.pci_dss.pass}' \
  -f json)

echo "$results" | jq '.' > "$RESULT_FILE"

if jq -e '.result[0].expressions[0].value.deny | length == 0' "$RESULT_FILE" > /dev/null; then
    echo "[✓] No PCI DSS drifts detected."
else
    echo "[✗] PCI DSS drifts found! Stored in $DRIFT_FILE"
fi

echo "[*] Full results (passes and fails) stored in $RESULT_FILE"
