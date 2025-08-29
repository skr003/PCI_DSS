echo "[*] Collecting Diagnostic Settings for supported resources..."
DIAGNOSTICS_FILE="$OUTPUT_DIR/diagnostics.json"
echo "[]" > $DIAGNOSTICS_FILE

# Filter resources that support diagnostics
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
