#!/bin/bash

set -e

OUTPUT_DIR="output"

mkdir -p $OUTPUT_DIR

echo "[*] Validating PCI DSS Req 10 with OPA..."

opa eval --input $OUTPUT_DIR/azure.json \
  --data policy/azure/pci_dss_req10.rego \
  'data.azure.pci_dss.req10.deny' \
  --format=json | jq '.result[0].expressions[0].value' > $OUTPUT_DIR/drift.json

opa eval --input $OUTPUT_DIR/azure.json \
  --data policy/azure/pci_dss_req10.rego \
  '{"deny": data.azure.pci_dss.req10.deny, "pass": data.azure.pci_dss.req10.pass}' \
  --format=json | jq '.result[0].expressions[0].value' > $OUTPUT_DIR/result.json

  
echo "[*] Validation complete."
echo " - Violations → $OUTPUT_DIR/drift.json"
