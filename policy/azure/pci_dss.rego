package azure.pci_dss

default allow = false
allow if { count(deny) == 0 }

###############################
# Shortcuts
###############################

azure_vms[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_virtual_machine"
}

azure_storage_accounts[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_storage_account"
}

azure_diagnostics[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_monitor_diagnostic_setting"
}

azure_log_analytics[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_log_analytics_workspace"
}

azure_metric_alerts[res] if {
  res := input.resource_changes[_]
  res.type == "azurerm_monitor_metric_alert"
}

###############################
# Helper Functions
###############################

# At least one log enabled in diagnostics
exists_enabled_log(d) if {
  some i
  d.values.logs[i].enabled
}

# Diagnostic settings configured for log review (proxy check)
logs_review_configured(d) if {
  d.values.logs_enabled
}

# Immutability enabled on storage account
immutability_enabled(sa) if {
  sa.values.immutable_storage_with_versioning.enabled
}

# VM boot diagnostics enabled
boot_diag_enabled(vm) if {
  vm.values.diagnostics_profile.boot_diagnostics.enabled
}

# Metric alert enabled
alert_enabled(a) if {
  a.values.enabled
}

# Log retention at least 365 days
retention_ok(ws) if {
  ws.values.retention_in_days >= 365
}

###############################
# PCI DSS Requirement 10 Rules
###############################

# 10.1 – Diagnostic logging enabled
deny[msg] if {
  some vm
  azure_vms[vm]
  not boot_diag_enabled(vm)
  msg := sprintf("PCI DSS Req 10.1 Violation: VM %s missing diagnostic logging.", [vm.name])
}

pass[msg] if {
  some vm
  azure_vms[vm]
  boot_diag_enabled(vm)
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

# 10.3 – Audit logs protected
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  not immutability_enabled(sa)
  msg := sprintf("PCI DSS Req 10.3 Violation: Storage account %s does not have immutability enabled.", [sa.name])
}

pass[msg] if {
  some sa
  azure_storage_accounts[sa]
  immutability_enabled(sa)
  msg := sprintf("PCI DSS Req 10.3 Passed: Storage account %s has immutability enabled.", [sa.name])
}

# 10.4 – Audit logs reviewed
deny[msg] if {
  some d
  azure_diagnostics[d]
  not logs_review_configured(d)
  msg := sprintf("PCI DSS Req 10.4 Violation: Diagnostic setting %s is missing log review configuration.", [d.name])
}

pass[msg] if {
  some d
  azure_diagnostics[d]
  logs_review_configured(d)
  msg := sprintf("PCI DSS Req 10.4 Passed: Diagnostic setting %s has log review configuration.", [d.name])
}

# 10.5 – Log retention
deny[msg] if {
  some ws
  azure_log_analytics[ws]
  not retention_ok(ws)
  msg := sprintf("PCI DSS Req 10.5 Violation: Log Analytics %s retains logs for less than 1 year.", [ws.name])
}

pass[msg] if {
  some ws
  azure_log_analytics[ws]
  retention_ok(ws)
  msg := sprintf("PCI DSS Req 10.5 Passed: Log Analytics %s retains logs for at least 1 year.", [ws.name])
}

# 10.6 – Time synchronization (proxy check via boot diagnostics)
deny[msg] if {
  some vm
  azure_vms[vm]
  not boot_diag_enabled(vm)
  msg := sprintf("PCI DSS Req 10.6 Violation: VM %s may not be time synchronized.", [vm.name])
}

pass[msg] if {
  some vm
  azure_vms[vm]
  boot_diag_enabled(vm)
  msg := sprintf("PCI DSS Req 10.6 Passed: VM %s has boot diagnostics (proxy for time sync).", [vm.name])
}

# 10.7 – Critical alerting enabled
deny[msg] if {
  some a
  azure_metric_alerts[a]
  not alert_enabled(a)
  msg := sprintf("PCI DSS Req 10.7 Violation: Metric alert %s is disabled.", [a.name])
}

pass[msg] if {
  some a
  azure_metric_alerts[a]
  alert_enabled(a)
  msg := sprintf("PCI DSS Req 10.7 Passed: Metric alert %s is enabled.", [a.name])
}
