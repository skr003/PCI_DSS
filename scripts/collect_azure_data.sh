#!/bin/bash
set -e

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

echo "[*] Collecting VM details..."
az vm list --query '[].{id:id,name:name,location:location,os:storageProfile.osDisk.osType}' -o json > $OUTPUT_DIR/vms.json

echo "[*] Collecting VM boot diagnostics..."
az vm list --query '[].{id:id,name:name,diagnostics_enabled:diagnosticsProfile.bootDiagnostics.enabled}' -o json > $OUTPUT_DIR/vm_diagnostics.json

echo "[*] Collecting Storage Accounts..."
az storage account list --query '[].{id:id,name:name,httpsOnly:enableHttpsTrafficOnly,publicAccess:allowBlobPublicAccess,immutable:immutableStorageWithVersioning}' -o json > $OUTPUT_DIR/storage.json

echo "[*] Collecting Diagnostic Settings for all VMs..."
echo "[]" > $OUTPUT_DIR/diagnostics.json
for id in $(az vm list --query "[].id" -o tsv); do
  az monitor diagnostic-settings list \
    --resource $id \
    -o json | jq -s 'add' \
    | jq -s '.[0] + .[1]' $OUTPUT_DIR/diagnostics.json - \
    > $OUTPUT_DIR/diagnostics.tmp.json
  mv $OUTPUT_DIR/diagnostics.tmp.json $OUTPUT_DIR/diagnostics.json
done

echo "[*] Collecting Log Analytics Workspaces..."
az monitor log-analytics workspace list --query '[].{id:id,name:name,retention_in_days:retentionInDays}' -o json > $OUTPUT_DIR/log_analytics.json

echo "[*] Collecting Metric Alerts for all VMs..."
echo "[]" > $OUTPUT_DIR/alerts.json
for id in $(az vm list --query "[].id" -o tsv); do
  az monitor metrics alert list \
    --query "[?contains(scopes, '$id')].{id:id,name:name,enabled:enabled,severity:severity,scopes:scopes}" \
    -o json | jq -s 'add' \
    | jq -s '.[0] + .[1]' $OUTPUT_DIR/alerts.json - \
    > $OUTPUT_DIR/alerts.tmp.json
  mv $OUTPUT_DIR/alerts.tmp.json $OUTPUT_DIR/alerts.json
done

echo "[*] Merging into azure.json..."
jq -n \
  --argfile vms $OUTPUT_DIR/vms.json \
  --argfile vm_diagnostics $OUTPUT_DIR/vm_diagnostics.json \
  --argfile storage $OUTPUT_DIR/storage.json \
  --argfile diagnostics $OUTPUT_DIR/diagnostics.json \
  --argfile log_analytics $OUTPUT_DIR/log_analytics.json \
  --argfile alerts $OUTPUT_DIR/alerts.json \
  '{resource_changes: ($vms + $vm_diagnostics + $storage + $diagnostics + $log_analytics + $alerts)}' > $OUTPUT_DIR/azure.json

echo "[*] Data collection complete → $OUTPUT_DIR/azure.json"
