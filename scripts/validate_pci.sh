#!/bin/bash
set -e

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

echo "[*] Validating PCI DSS Req 10 with OPA..."

# Violations only → drift.json (JSON array)
opa eval --input $OUTPUT_DIR/azure.json \
  --data policy/azure/pci_dss_req10.rego \
  'data.azure.pci_dss.req10.deny' \
  --format=json | jq '.result[0].expressions[0].value' > $OUTPUT_DIR/drift.json

# Both passes & violations → result.json (JSON object)
opa eval --input $OUTPUT_DIR/azure.json \
  --data policy/azure/pci_dss_req10.rego \
  '{"deny": data.azure.pci_dss.req10.deny, "pass": data.azure.pci_dss.req10.pass}' \
  --format=json | jq '.result[0].expressions[0].value' > $OUTPUT_DIR/result.json

# Optional summary
deny_count=$(jq 'length' $OUTPUT_DIR/drift.json)
pass_count=$(jq '.pass | length' $OUTPUT_DIR/result.json)

echo "[*] Validation complete."
echo "    - Violations → $OUTPUT_DIR/drift.json ($deny_count)"
echo "    - Full report → $OUTPUT_DIR/result.json (Pass: $pass_count / Fail: $deny_count)"
