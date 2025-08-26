package pci_dss

default allow = false

# Allow only if there are no denies
allow if {
  count(deny) == 0
}

# DENY RULES

# PCI DSS 3.4: Storage must enforce HTTPS
deny[msg] if {
  some s
  input.resource_changes[s].type == "azurerm_storage_account"
  input.resource_changes[s].values.enable_https_traffic_only == false
  msg := sprintf("PCI DSS 3.4 Violation: Storage account %s does not enforce HTTPS", [input.resource_changes[s].name])
}

# PCI DSS 1.2: Storage must block public blob access
deny[msg] if {
  some s
  input.resource_changes[s].type == "azurerm_storage_account"
  input.resource_changes[s].values.allow_blob_public_access == true
  msg := sprintf("PCI DSS 1.2 Violation: Storage account %s allows public blob access", [input.resource_changes[s].name])
}

# PCI DSS 2.2.1: VMs must specify OS
deny[msg] if {
  some v
  input.resource_changes[v].type == "azurerm_linux_virtual_machine"
  not input.resource_changes[v].values.os_disk[0].os_type
  msg := sprintf("PCI DSS 2.2.1 Violation: VM %s does not specify OS type", [input.resource_changes[v].name])
}
