package azure.pci_dss

default allow = false

# Allow if no denies
allow if {
  count(deny) == 0
}

# Collector: gather all Azure Storage Accounts
azure_storage_accounts[sa] if {
  sa := input.resource_changes[_]
  sa.type == "azurerm_storage_account"
}

# 10.1 Ensure that 'Secure transfer required' is enabled
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  not sa.values.enable_https_traffic_only
  msg := sprintf("PCI DSS Req 10.1 Violation: Storage account %s does not enforce HTTPS-only traffic.", [sa.name])
}

# 10.2 Ensure that 'Minimum TLS version' is set to 1.2
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  not sa.values.min_tls_version
  msg := sprintf("PCI DSS Req 10.2 Violation: Storage account %s does not specify a minimum TLS version.", [sa.name])
}

deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  sa.values.min_tls_version != "TLS1_2"
  msg := sprintf("PCI DSS Req 10.2 Violation: Storage account %s uses %s instead of TLS1_2.", [sa.name, sa.values.min_tls_version])
}

# 10.3 Ensure that 'Public network access' is disabled
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  sa.values.public_network_access == "Enabled"
  msg := sprintf("PCI DSS Req 10.3 Violation: Storage account %s allows public network access.", [sa.name])
}

# 10.4 Ensure storage account logging is enabled (Blob, Table, Queue)
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  not sa.values.blob_properties.logging.delete
  not sa.values.blob_properties.logging.read
  not sa.values.blob_properties.logging.write
  msg := sprintf("PCI DSS Req 10.4 Violation: Storage account %s does not have logging enabled for Blob service.", [sa.name])
}

# 10.5 Ensure that soft delete is enabled for Blob service
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  not sa.values.blob_properties.delete_retention_policy.enabled
  msg := sprintf("PCI DSS Req 10.5 Violation: Storage account %s does not have soft delete enabled for Blobs.", [sa.name])
}

# 10.6 Ensure that soft delete is enabled for File service
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  not sa.values.file_properties.share_delete_retention_policy.enabled
  msg := sprintf("PCI DSS Req 10.6 Violation: Storage account %s does not have soft delete enabled for File shares.", [sa.name])
}

##############################
# Helper: NSG deny-all check
##############################

nsg_has_deny_all(nsg) if {
  some i
  sec_rule := nsg.values.security_rule[i]
  sec_rule.direction == "Inbound"
  sec_rule.access == "Deny"
  sec_rule.priority == 4096
}

##############################
# Input shortcuts
##############################

azure_storage_accounts[r] if {
  r := input.resource_changes[_]
  r.type == "azurerm_storage_account"
}

azure_vms[r] if {
  r := input.resource_changes[_]
  r.type == "azurerm_linux_virtual_machine"
}

azure_vms[r] if {
  r := input.resource_changes[_]
  r.type == "azurerm_windows_virtual_machine"
}

azure_identities[r] if {
  r := input.resource_changes[_]
  r.type == "azurerm_user"
}

azure_identities[r] if {
  r := input.resource_changes[_]
  r.type == "azurerm_ad_user"
}

azure_nsgs[r] if {
  r := input.resource_changes[_]
  r.type == "azurerm_network_security_group"
}

azure_disks[r] if {
  r := input.resource_changes[_]
  r.type == "azurerm_managed_disk"
}

azure_resources[r] if {
  r := input.resource_changes[_]
}
