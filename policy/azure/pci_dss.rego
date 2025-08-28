package azure.pci_dss

default allow = false

allow if {
  count(deny) == 0
}

##############################
# PCI DSS Diagnostic Logging
##############################

# Violation (fail)
deny[msg] if {
  some r
  azure_resources[r]
  not r.values.diagnostics_profile.boot_diagnostics.enabled
  msg := sprintf("PCI DSS Req 10 Violation: Resource %s missing diagnostic logging.", [r.name])
}

# Compliant (pass)
pass[msg] if {
  some r
  azure_resources[r]
  r.values.diagnostics_profile.boot_diagnostics.enabled
  msg := sprintf("PCI DSS Req 10 Passed: Resource %s has diagnostic logging enabled.", [r.name])
}
