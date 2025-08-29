#!/bin/bash
set -e

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

echo "[*] Validating PCI DSS Req 10 with OPA..."

# Violations only → drift.json
opa eval --input $OUTPUT_DIR/azure.json \
  --data policy/azure/pci_dss.rego \
  'data.azure.pci_dss.deny' \
  --format=json -o values > $OUTPUT_DIR/drift.json

# Both passes & violations → result.json
opa eval --input $OUTPUT_DIR/azure.json \
  --data policy/azure/pci_dss.rego \
  '{"deny": data.azure.pci_dss.deny, "pass": data.azure.pci.pass}' \
  --format=json -o values > $OUTPUT_DIR/result.json

echo "[*] Validation complete."
echo "    - Violations → $OUTPUT_DIR/drift.json"
echo "    - Full report → $OUTPUT_DIR/result.json"
