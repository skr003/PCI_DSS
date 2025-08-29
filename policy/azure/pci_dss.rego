package azurecli.pci_dss.req10

# Input shape:
# {
#   "vms": [ { name, type: "Microsoft.Compute/virtualMachines", diagnostics_enabled: bool, diagnosticsProfile: {...} } ],
#   "storage": [ { name, type: "Microsoft.Storage/storageAccounts", immutability_enabled: bool, enableHttpsTrafficOnly: bool } ],
#   "diagnostics": [ { name, resourceId, logs: [ {enabled: bool, category, ...}, ... ] } ],
#   "workspaces": [ { name, retentionInDays: number } ],
#   "alerts": [ { name, enabled: bool } ]
# }

###############################
# Shortcuts (work directly on Azure CLI JSON)
###############################

azure_vms[vm]          { vm := input.vms[_] }
azure_diagnostics[ds]  { ds := input.diagnostics[_] }
azure_workspaces[ws]   { ws := input.workspaces[_] }
azure_metric_alerts[a] { a := input.alerts[_] }

###############################
# Helper checks
###############################

vm_boot_diag_enabled(vm) {
  vm.diagnostics_enabled == true
}

diag_has_enabled_log(ds) {
  some i
  ds.logs[i].enabled == true
}

workspace_retention_ok(ws) {
  ws.retentionInDays >= 365
}

metric_alert_enabled(a) {
  a.enabled == true
}

###############################
# PCI DSS Req 10 rules
###############################

# 10.1 – Diagnostic logging enabled (VM boot diagnostics proxy)
deny[msg] {
  vm := azure_vms[_]
  not vm_boot_diag_enabled(vm)
  msg := sprintf("PCI DSS Req 10.1 Violation: VM %s missing diagnostic logging.", [vm.name])
}

pass[msg] {
  vm := azure_vms[_]
  vm_boot_diag_enabled(vm)
  msg := sprintf("PCI DSS Req 10.1 Passed: VM %s has diagnostic logging enabled.", [vm.name])
}

# 10.2 – Audit logs implemented (diagnostic settings have at least one enabled log)
deny[msg] {
  ds := azure_diagnostics[_]
  not diag_has_enabled_log(ds)
  msg := sprintf("PCI DSS Req 10.2 Violation: Diagnostic setting %s has no audit logs enabled.", [ds.name])
}

pass[msg] {
  ds := azure_diagnostics[_]
  diag_has_enabled_log(ds)
  msg := sprintf("PCI DSS Req 10.2 Passed: Diagnostic setting %s has audit logs enabled.", [ds.name])
}

# 10.5 – Log retention at least 1 year
deny[msg] {
  ws := azure_workspaces[_]
  not workspace_retention_ok(ws)
  msg := sprintf("PCI DSS Req 10.5 Violation: Log Analytics workspace %s retains logs for less than 1 year (%d days).", [ws.name, ws.retentionInDays])
}

pass[msg] {
  ws := azure_workspaces[_]
  workspace_retention_ok(ws)
  msg := sprintf("PCI DSS Req 10.5 Passed: Log Analytics workspace %s retains logs for at least 1 year (%d days).", [ws.name, ws.retentionInDays])
}

# 10.7 – Critical security control alerting is enabled (metric alerts)
deny[msg] {
  a := azure_metric_alerts[_]
  not metric_alert_enabled(a)
  msg := sprintf("PCI DSS Req 10.7 Violation: Metric alert %s is disabled.", [a.name])
}

pass[msg] {
  a := azure_metric_alerts[_]
  metric_alert_enabled(a)
  msg := sprintf("PCI DSS Req 10.7 Passed: Metric alert %s is enabled.", [a.name])
}
