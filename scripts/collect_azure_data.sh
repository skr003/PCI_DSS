#!/bin/bash

set -e

OUTPUT_DIR="output"

mkdir -p $OUTPUT_DIR

echo "[*] Collecting VMs..."

az vm list -d -o json \
| jq '[ .[] | {
type: "azurerm_virtual_machine",
name: .name,
values: {
diagnostics_profile: {
boot_diagnostics: {
enabled: ( .diagnosticsProfile.bootDiagnostics.enabled // false )
}
}
}
}]' > $OUTPUT_DIR/vms.json

echo "[*] Collecting Storage Accounts..."

az storage account list -o json \
| jq '[ .[] | {
type: "azurerm_storage_account",
name: .name,
values: {
enable_https_traffic_only: ( .enableHttpsTrafficOnly // false ),
immutable_storage_with_versioning: {
enabled: ( .immutableStorageWithVersioning.enabled // false )
}
}
}]' > $OUTPUT_DIR/storage.json

echo "[*] Collecting Diagnostic Settings..."

DIAGNOSTICS_FILE="$OUTPUT_DIR/diagnostics.json"
echo "[]" > $DIAGNOSTICS_FILE

for rid in $(az resource list --query "[?type=='Microsoft.Compute/virtualMachines' || type=='Microsoft.Storage/storageAccounts' || type=='Microsoft.KeyVault/vaults'].id" -o tsv); do
ds=$(az monitor diagnostic-settings list --resource "$rid" -o json)
if [ "$ds" != "[]" ]; then
echo "$ds" | jq --arg rid "$rid" '[ .[] | {
type: "azurerm_monitor_diagnostic_setting",
name: .name,
values: {
resourceId: $rid,
logs: ( .logs // [] )
}
}]' | jq -s 'add' > tmp.json
jq -s 'add' $DIAGNOSTICS_FILE tmp.json > merged.json
mv merged.json $DIAGNOSTICS_FILE
rm -f tmp.json
fi
done

echo "[*] Collecting Log Analytics Workspaces..."

az monitor log-analytics workspace list -o json \
| jq '[ .[] | {
type: "azurerm_log_analytics_workspace",
name: .name,
values: {
retention_in_days: ( .retentionInDays // 0 )
}
}]' > $OUTPUT_DIR/log_analytics.json

echo "[*] Collecting Metric Alerts..."

ALERTS_FILE="$OUTPUT_DIR/alerts.json"
echo "[]" > $ALERTS_FILE

for rid in $(az resource list --resource-type "Microsoft.Insights/metricAlerts" --query "[].id" -o tsv); do
alert=$(az resource show --ids "$rid" -o json)
echo "$alert" | jq '[{
type: "azurerm_monitor_metric_alert",
name: .name,
values: {
enabled: ( .properties.enabled // false )
}
}]' > tmp.json
jq -s 'add' $ALERTS_FILE tmp.json > merged.json
mv merged.json $ALERTS_FILE
rm -f tmp.json
done

echo "[*] Merging into azure.json..."

jq -s '{resource_changes: add}' \
$OUTPUT_DIR/vms.json \
$OUTPUT_DIR/storage.json \
$OUTPUT_DIR/diagnostics.json \
$OUTPUT_DIR/log_analytics.json \
$OUTPUT_DIR/alerts.json \
> $OUTPUT_DIR/azure.json

echo "[*] Data collection complete → $OUTPUT_DIR/azure.json"
