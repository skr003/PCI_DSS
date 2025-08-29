#!/bin/bash
set -e

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

echo "[*] Collecting Azure VM details..."
az vm list --query '[].{name:name,location:location,os:storageProfile.osDisk.osType}' -o json > $OUTPUT_DIR/vms.json

echo "[*] Collecting Azure Storage Account details..."
az storage account list --query '[].{name:name,httpsOnly:enableHttpsTrafficOnly,publicAccess:allowBlobPublicAccess}' -o json > $OUTPUT_DIR/storage.json

echo "[*] Merging into tfplan.json style input..."
jq -n \
  --argfile vms $OUTPUT_DIR/vms.json \
  --argfile storage $OUTPUT_DIR/storage.json \
  '{resource_changes: ($vms + $storage)}' > $OUTPUT_DIR/azure.json

echo "[*] Azure data saved to $OUTPUT_DIR/azure.json"
