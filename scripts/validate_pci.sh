#!/bin/bash
set -e

INPUT="output/azure.json"
POLICY="policy/azure/pci_dss.rego"

echo "[*] Running PCI DSS validation with OPA..."
opa eval --format pretty --input $INPUT --data $POLICY "data.pci_dss.deny"
