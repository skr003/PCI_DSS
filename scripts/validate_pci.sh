#!/bin/bash
set -euo pipefail

OUTPUT_DIR="output"
DRIFT_FILE="${OUTPUT_DIR}/pci_dss_drifts.json"

mkdir -p "$OUTPUT_DIR"

echo "[*] Running PCI DSS validation with OPA..."

violations=$(opa eval \
  --input output/azure.json \
  --data policy/azure/pci_dss.rego \
  "data.azure.pci_dss.deny" \
  -f json)

echo "$violations" | jq '.' > "$DRIFT_FILE"

if jq -e '.result[0].expressions[0].value | length == 0' "$DRIFT_FILE" > /dev/null; then
    echo "[✓] No PCI DSS drifts detected."
else
    echo "[✗] PCI DSS drifts found! Stored in $DRIFT_FILE"
fi
