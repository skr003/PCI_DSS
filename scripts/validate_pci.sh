#!/bin/bash
set -e

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

# Redirect status message to stderr to keep stdout clean for JSON output
echo "[*] Validating PCI DSS Req 10 with OPA..." >&2

# Evaluate the 'deny' rule and pipe the JSON array output directly to stdout
opa eval --input $OUTPUT_DIR/azure.json \
  --data policy/azure/pci_dss_req10.rego \
  'data.azure.pci_dss.req10.deny' \
  --format=json | jq '.result[0].expressions[0].value'
