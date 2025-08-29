package azure.pci_dss.req10

# Shortcuts
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

# Helper rules
boot_diag_enabled(vm) if {
  vm.values.diagnostics_profile.boot_diagnostics.enabled
}

exists_enabled_log(d) if {
  some i
  d.values.logs[i].enabled
}

retention_ok(la) if {
  la.values.retention_in_days >= 90
}

metric_alert_enabled(a) if {
  a.values.enabled
}

# Requirement 10.1
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

# Requirement 10.2
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

# Requirement 10.5 (log retention)
deny[msg] if {
  some la
  azure_log_analytics[la]
  not retention_ok(la)
  msg := sprintf("PCI DSS Req 10.5 Violation: Log Analytics workspace %s has insufficient retention (%d days).", [la.name, la.values.retention_in_days])
}

pass[msg] if {
  some la
  azure_log_analytics[la]
  retention_ok(la)
  msg := sprintf("PCI DSS Req 10.5 Passed: Log Analytics workspace %s meets retention policy (%d days).", [la.name, la.values.retention_in_days])
}

# Requirement 10.7 (alerts configured)
deny[msg] if {
  some a
  azure_metric_alerts[a]
  not metric_alert_enabled(a)
  msg := sprintf("PCI DSS Req 10.7 Violation: Metric alert %s is disabled.", [a.name])
}

pass[msg] if {
  some a
  azure_metric_alerts[a]
  metric_alert_enabled(a)
  msg := sprintf("PCI DSS Req 10.7 Passed: Metric alert %s is enabled.", [a.name])
}
