#!/bin/bash
set -euo pipefail

OUTPUT_DIR="output"
POLICY_FILE="policy/azure/pci_dss_req10.rego"

mkdir -p "$OUTPUT_DIR"

if [ ! -f "$OUTPUT_DIR/azure.json" ]; then
  echo "ERROR: $OUTPUT_DIR/azure.json not found. Run collect_azure_data.sh first." >&2
  exit 1
fi

echo "[*] Validating PCI DSS Req 10 with OPA..."

# Violations only → drift.json (JSON array of strings)
opa eval --input "$OUTPUT_DIR/azure.json" \
  --data "$POLICY_FILE" \
  'data.azurecli.pci_dss.req10.deny' \
  --format=json | jq '.result[0].expressions[0].value' > "$OUTPUT_DIR/drift.json"

# Both passes & violations → result.json (JSON object with arrays)
opa eval --input "$OUTPUT_DIR/azure.json" \
  --data "$POLICY_FILE" \
  '{"deny": data.azurecli.pci_dss.req10.deny, "pass": data.azurecli.pci_dss.req10.pass}' \
  --format=json | jq '.result[0].expressions[0].value' > "$OUTPUT_DIR/result.json"

# Summary to console
deny_count=$(jq 'length' "$OUTPUT_DIR/drift.json")
pass_count=$(jq '.pass | length' "$OUTPUT_DIR/result.json")

echo "[*] Validation complete."
echo "    - Violations → $OUTPUT_DIR/drift.json ($deny_count)"
echo "    - Full report → $OUTPUT_DIR/result.json (Pass: $pass_count / Fail: $deny_count)"
