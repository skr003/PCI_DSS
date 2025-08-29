package azure.pci_dss

default allow = false
allow if { count(deny) == 0 }

###############################
# Shortcuts
###############################

# All Virtual Machines
azure_vms[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_virtual_machine"
}

# All Storage Accounts
azure_storage_accounts[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_storage_account"
}

# All Diagnostic Settings
azure_diagnostics[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_monitor_diagnostic_setting"
}

# All Log Analytics Workspaces
azure_log_analytics[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_log_analytics_workspace"
}

# All Metric Alerts
azure_metric_alerts[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_monitor_metric_alert"
}

###############################
# PCI DSS Requirement 10 Rules
###############################

# 10.1 – Diagnostic logging enabled
deny[msg] if {
  some vm
  azure_vms[vm]
  not vm.values.diagnostics_profile.boot_diagnostics.enabled
  msg := sprintf("PCI DSS Req 10.1 Violation: VM %s missing diagnostic logging.", [vm.name])
}

pass[msg] if {
  some vm
  azure_vms[vm]
  vm.values.diagnostics_profile.boot_diagnostics.enabled
  msg := sprintf("PCI DSS Req 10.1 Passed: VM %s has diagnostic logging enabled.", [vm.name])
}

# 10.2 – Audit logs implemented
deny[msg] if {
  some d
  azure_diagnostics[d]
  not exists_enabled_log(d)
  msg := sprintf("PCI DSS Req 10.2 Violation: Diagnostic setting %s has no audit logs enabled.", [d.name])
}

pass[msg] if {
  some d
  azure_diagnostics[d]
  exists_enabled_log(d)
  msg := sprintf("PCI DSS Req 10.2 Passed: Diagnostic setting %s has audit logs enabled.", [d.name])
}

# Helper function
exists_enabled_log(d) {
  some log
  log := d.values.logs[_]
  log.enabled
}


# 10.3 – Audit logs protected
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  not sa.values.immutable_storage_with_versioning.enabled
  msg := sprintf("PCI DSS Req 10.3 Violation: Storage account %s does not have immutability enabled.", [sa.name])
}

pass[msg] if {
  some sa
  azure_storage_accounts[sa]
  sa.values.immutable_storage_with_versioning.enabled
  msg := sprintf("PCI DSS Req 10.3 Passed: Storage account %s has immutability enabled.", [sa.name])
}

# 10.4 – Audit logs reviewed
deny[msg] if {
  some d
  azure_diagnostics[d]
  not d.values.logs_enabled
  msg := sprintf("PCI DSS Req 10.4 Violation: Diagnostic setting %s is missing log review configuration.", [d.name])
}

pass[msg] if {
  some d
  azure_diagnostics[d]
  d.values.logs_enabled
  msg := sprintf("PCI DSS Req 10.4 Passed: Diagnostic setting %s has log review configuration.", [d.name])
}

# 10.5 – Log retention
deny[msg] if {
  some ws
  azure_log_analytics[ws]
  ws.values.retention_in_days < 365
  msg := sprintf("PCI DSS Req 10.5 Violation: Log Analytics %s retains logs for less than 1 year.", [ws.name])
}

pass[msg] if {
  some ws
  azure_log_analytics[ws]
  ws.values.retention_in_days >= 365
  msg := sprintf("PCI DSS Req 10.5 Passed: Log Analytics %s retains logs for at least 1 year.", [ws.name])
}

# 10.6 – Time synchronization
deny[msg] if {
  some vm
  azure_vms[vm]
  not vm.values.diagnostics_profile.boot_diagnostics.enabled   # proxy
  msg := sprintf("PCI DSS Req 10.6 Violation: VM %s may not be time synchronized.", [vm.name])
}

pass[msg] if {
  some vm
  azure_vms[vm]
  vm.values.diagnostics_profile.boot_diagnostics.enabled
  msg := sprintf("PCI DSS Req 10.6 Passed: VM %s has boot diagnostics (proxy for time sync).", [vm.name])
}

# 10.7 – Critical alerting enabled
deny[msg] if {
  some a
  azure_metric_alerts[a]
  not a.values.enabled
  msg := sprintf("PCI DSS Req 10.7 Violation: Metric alert %s is disabled.", [a.name])
}

pass[msg] if {
  some a
  azure_metric_alerts[a]
  a.values.enabled
  msg := sprintf("PCI DSS Req 10.7 Passed: Metric alert %s is enabled.", [a.name])
}
