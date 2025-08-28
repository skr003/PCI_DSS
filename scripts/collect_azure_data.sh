#!/bin/bash
set -e

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

echo "[*] Collecting Azure VM details..."
az vm list -o json > $OUTPUT_DIR/vms.json
az vm list --query '[].{name:name,location:location,os:storageProfile.osDisk.osType}' -o json > $OUTPUT_DIR/vms.json
az vm list --query '[].{name:name, diagnostics:diagnosticsProfile.bootDiagnostics}' -o json > $OUTPUT_DIR/vm_diagnostics.json

for id in $(az resource list --query "[].id" -o tsv); do
  echo "Checking diagnostics for: $id"
  az monitor diagnostic-settings list \
    --resource $id \
    -o json >> $OUTPUT_DIR/diagnostics.json
done

echo "[*] Collecting Azure Storage Account details..."
az storage account list --query '[].{name:name,httpsOnly:enableHttpsTrafficOnly,publicAccess:allowBlobPublicAccess,immutability:immutableStorageWithVersioning}' -o json > $OUTPUT_DIR/storage.json
az storage account list --query '[].{name:name,httpsOnly:enableHttpsTrafficOnly,publicAccess:allowBlobPublicAccess}' -o json > $OUTPUT_DIR/storage.json
az storage account list --query '[].{id:id,name:name,resourceGroup:resourceGroup,location:location}' -o json > $OUTPUT_DIR/storage.json

# For each storage account, collect blob service properties (soft delete info)
for rg in $(az storage account list --query '[].resourceGroup' -o tsv); do
  for sa in $(az storage account list --resource-group $rg --query '[].name' -o tsv); do
    echo "Collecting blob service properties for $sa in $rg..."
    az storage account blob-service-properties show \
      --account-name "$sa" \
      --resource-group "$rg" \
      --query '{name:name, deleteRetentionPolicy:deleteRetentionPolicy}' \
      -o json >> $OUTPUT_DIR/storage.json
  done
done

echo "[*] Merging into tfplan.json style input..."
jq -n \
  --argfile vms $OUTPUT_DIR/vms.json \
  --argfile storage $OUTPUT_DIR/storage.json \
  '{resource_changes: ($vms + $storage)}' > $OUTPUT_DIR/azure.json

echo "[*] Azure data saved to $OUTPUT_DIR/azure.json"
