#!/bin/bash
set -e

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

echo "[*] Validating PCI DSS Req 10 with OPA..."

# Violations only → drift.json
opa eval --input $OUTPUT_DIR/azure.json \
  --data pci_dss_req10.rego \
  'data.azure.pci_dss.req10.deny' \
  --format=json > $OUTPUT_DIR/drift.json

# Both passes & violations → result.json
opa eval --input $OUTPUT_DIR/azure.json \
  --data pci_dss_req10.rego \
  '{"deny": data.azure.pci_dss.req10.deny, "pass": data.azure.pci_dss.req10.pass}' \
  --format=json > $OUTPUT_DIR/result.json

echo "[*] Validation complete."
echo "    - Violations → $OUTPUT_DIR/drift.json"
echo "    - Full report → $OUTPUT_DIR/result.json"
