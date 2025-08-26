#!/bin/bash
set -e

INPUT="output/azure.json"
POLICY="policies/pci_dss.rego"

echo "[*] Running PCI DSS validation with OPA..."
opa eval --format pretty --input $INPUT --data $POLICY "data.pci_dss.deny"
