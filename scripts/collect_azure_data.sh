#!/bin/bash
set -e

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

echo "[*] Collecting VMs..."
az vm list --query '[].{name:name, diagnostics:diagnosticsProfile.bootDiagnostics.enabled}' -o json \
| jq '[ .[] | {
    type: "azurerm_virtual_machine",
    name: .name,
    values: {
      diagnostics_profile: {
        boot_diagnostics: {
          enabled: .diagnostics
        }
      }
    }
  }]' > $OUTPUT_DIR/vms.json

echo "[*] Collecting Storage Accounts..."
az storage account list --query '[].{name:name, httpsOnly:enableHttpsTrafficOnly, immutability:immutableStorageWithVersioning}' -o json \
| jq '[ .[] | {
    type: "azurerm_storage_account",
    name: .name,
    values: {
      enable_https_traffic_only: .httpsOnly,
      immutable_storage_with_versioning: {
        enabled: (.immutability != null and .immutability.enabled == true)
      }
    }
  }]' > $OUTPUT_DIR/storage.json

echo "[*] Collecting Diagnostic Settings..."
az monitor diagnostic-settings list --resource-group <your-rg> -o json \
| jq '[ .[] | {
    type: "azurerm_monitor_diagnostic_setting",
    name: .name,
    values: {
      logs: .logs
    }
  }]' > $OUTPUT_DIR/diagnostics.json

echo "[*] Collecting Log Analytics Workspaces..."
az monitor log-analytics workspace list --query '[].{name:name, retention:retentionInDays}' -o json \
| jq '[ .[] | {
    type: "azurerm_log_analytics_workspace",
    name: .name,
    values: {
      retention_in_days: .retention
    }
  }]' > $OUTPUT_DIR/log_analytics.json

echo "[*] Collecting Metric Alerts..."
az monitor metrics alert list -o json \
| jq '[ .[] | {
    type: "azurerm_monitor_metric_alert",
    name: .name,
    values: {
      enabled: .enabled
    }
  }]' > $OUTPUT_DIR/alerts.json

echo "[*] Merging into azure.json..."
jq -s '{resource_changes: add}' \
  $OUTPUT_DIR/vms.json \
  $OUTPUT_DIR/storage.json \
  $OUTPUT_DIR/diagnostics.json \
  $OUTPUT_DIR/log_analytics.json \
  $OUTPUT_DIR/alerts.json \
  > $OUTPUT_DIR/azure.json

echo "[*] Data collection complete → $OUTPUT_DIR/azure.json"
