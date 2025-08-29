#!/bin/bash
set -euo pipefail

# Requires: az, jq
OUTPUT_DIR="output"
mkdir -p "$OUTPUT_DIR"

echo "[*] Collecting Virtual Machines..."
az vm list -d -o json > "$OUTPUT_DIR/vms_raw.json"

echo "[*] Collecting Storage Accounts..."
az storage account list -o json > "$OUTPUT_DIR/storage_raw.json"

echo "[*] Collecting Diagnostic Settings for VMs and Storage Accounts..."
DIAG_FILE="$OUTPUT_DIR/diagnostics_raw.json"
echo "[]" > "$DIAG_FILE"

# Collect VM IDs
VM_IDS=$(az vm list --query "[].id" -o tsv)
for rid in $VM_IDS; do
  ds=$(az monitor diagnostic-settings list --resource "$rid" -o json)
  if [ "$ds" != "[]" ]; then
    echo "$ds" | jq --arg rid "$rid" '[ .[] | { name, resourceId: $rid, logs: (.logs // []) } ]' \
    | jq -s 'add' > tmp.json
    jq -s 'add' "$DIAG_FILE" tmp.json > merged.json
    mv merged.json "$DIAG_FILE"
    rm -f tmp.json
  fi
done

# Collect Storage Account IDs
SA_IDS=$(az storage account list --query "[].id" -o tsv)
for rid in $SA_IDS; do
  ds=$(az monitor diagnostic-settings list --resource "$rid" -o json)
  if [ "$ds" != "[]" ]; then
    echo "$ds" | jq --arg rid "$rid" '[ .[] | { name, resourceId: $rid, logs: (.logs // []) } ]' \
    | jq -s 'add' > tmp.json
    jq -s 'add' "$DIAG_FILE" tmp.json > merged.json
    mv merged.json "$DIAG_FILE"
    rm -f tmp.json
  fi
done

echo "[*] Collecting Log Analytics Workspaces..."
az monitor log-analytics workspace list -o json > "$OUTPUT_DIR/workspaces_raw.json"

echo "[*] Collecting Metric Alerts..."
ALERTS_FILE="$OUTPUT_DIR/alerts_raw.json"
echo "[]" > "$ALERTS_FILE"
for rid in $(az resource list --resource-type "Microsoft.Insights/metricAlerts" --query "[].id" -o tsv); do
  az resource show --ids "$rid" -o json \
  | jq '[{
      id, name,
      enabled: (.properties.enabled // false)
    }]' > tmp.json
  jq -s 'add' "$ALERTS_FILE" tmp.json > merged.json
  mv merged.json "$ALERTS_FILE"
  rm -f tmp.json
done

echo "[*] Building unified input (azure.json) for OPA..."
jq -n \
  --argfile vms "$OUTPUT_DIR/vms_raw.json" \
  --argfile storage "$OUTPUT_DIR/storage_raw.json" \
  --argfile diagnostics "$OUTPUT_DIR/diagnostics_raw.json" \
  --argfile workspaces "$OUTPUT_DIR/workspaces_raw.json" \
  --argfile alerts "$OUTPUT_DIR/alerts_raw.json" \
  '{
    vms: ($vms | map({
      id, name, type: "Microsoft.Compute/virtualMachines",
      diagnosticsProfile: (.diagnosticsProfile // {}),
      # Normalize bootDiagnostics flag for convenience
      diagnostics_enabled: ((.diagnosticsProfile.bootDiagnostics.enabled // false))
    })),
    storage: ($storage | map({
      id, name, type: "Microsoft.Storage/storageAccounts",
      enableHttpsTrafficOnly: (.enableHttpsTrafficOnly // false),
      immutableStorageWithVersioning: (.immutableStorageWithVersioning // {}),
      # Normalize immutability flag
      immutability_enabled: ((.immutableStorageWithVersioning.enabled // false))
    })),
    diagnostics: $diagnostics,
    workspaces: ($workspaces | map({
      id, name, retentionInDays: (.retentionInDays // 0)
    })),
    alerts: ($alerts | map({
      id, name, enabled
    }))
  }' > "$OUTPUT_DIR/azure.json"

echo "[*] Done → $OUTPUT_DIR/azure.json"
