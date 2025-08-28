#!/bin/bash
set -e

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

echo "[*] Collecting Azure VM details with diagnostics..."
az vm list --query '[].{name:name,location:location,os:storageProfile.osDisk.osType}' -o json > $OUTPUT_DIR/vms.json

# Collect VM boot diagnostics (10.1, 10.6)
az vm list --query '[].{name:name, diagnostics:diagnosticsProfile.bootDiagnostics}' -o json > $OUTPUT_DIR/vm_diagnostics.json

echo "[*] Collecting Azure Storage Account details..."
az storage account list --query '[].{name:name,httpsOnly:enableHttpsTrafficOnly,publicAccess:allowBlobPublicAccess,immutability:immutableStorageWithVersioning}' -o json > $OUTPUT_DIR/storage.json

echo "[*] Collecting Azure Diagnostic Settings (audit logs)..."
az monitor diagnostic-settings list --query '[].{name:name,resourceId:resourceId,logs:logs}' -o json > $OUTPUT_DIR/diagnostics.json

echo "[*] Collecting Azure Log Analytics Workspace retention..."
az monitor log-analytics workspace list --query '[].{name:name,retentionInDays:retentionInDays}' -o json > $OUTPUT_DIR/log_analytics.json

echo "[*] Collecting Azure Metric Alerts (critical alerting)..."
az monitor metrics alert list --query '[].{name:name,enabled:enabled,severity:severity}' -o json > $OUTPUT_DIR/alerts.json

echo "[*] Merging into tfplan.json style input..."
jq -n \
  --argfile vms $OUTPUT_DIR/vms.json \
  --argfile vm_diagnostics $OUTPUT_DIR/vm_diagnostics.json \
  --argfile storage $OUTPUT_DIR/storage.json \
  --argfile diagnostics $OUTPUT_DIR/diagnostics.json \
  --argfile log_analytics $OUTPUT_DIR/log_analytics.json \
  --argfile alerts $OUTPUT_DIR/alerts.json \
  '{resource_changes: ($vms + $vm_diagnostics + $storage + $diagnostics + $log_analytics + $alerts)}' > $OUTPUT_DIR/azure.json

echo "[*] Azure data saved to $OUTPUT_DIR/azure.json"
