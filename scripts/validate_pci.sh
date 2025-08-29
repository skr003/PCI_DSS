#!/bin/bash

set -e

OUTPUT_DIR="output"

mkdir -p $OUTPUT_DIR

echo "[*] Validating PCI DSS Req 10 with OPA..."

# Violations only → drift.json (JSON array)
opa eval --input $OUTPUT_DIR/azure.json \
  --data policy/azure/pci_dss_req10.rego \
  'data.azure.pci_dss.req10.deny' \
  --format=json | jq '.result.expressions.value' > $OUTPUT_DIR/drift.json

echo "[*] Validation complete."
echo " - Violations → $OUTPUT_DIR/drift.json"
