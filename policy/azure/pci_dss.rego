package azure.pci_dss

default allow = false

# Allow if no denies
allow if {
  count(deny) == 0
}

##############################
# Requirement 3 – Protect Stored Account Data
##############################

# Storage must enforce HTTPS
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  not sa.values.enable_https_traffic_only
  msg := sprintf("PCI DSS Req 3 Violation: Storage account %s does not enforce HTTPS-only traffic.", [sa.name])
}

# Storage must block blob public access
deny[msg] if {
  some sa
  azure_storage_accounts[sa]
  sa.values.allow_blob_public_access == true
  msg := sprintf("PCI DSS Req 3 Violation: Storage account %s allows public blob access.", [sa.name])
}

##############################
# Requirement 6 – Develop and Maintain Secure Systems and Apps
##############################

# Ensure VMs patched recently (example <= 30 days)
deny[msg] if {
  some vm
  azure_vms[vm]
  vm.values.days_since_last_patch > 0
  msg := sprintf("PCI DSS Req 6 Violation: VM %s not patched in %d days.", [vm.name, vm.values.days_since_last_patch])
}

##############################
# Requirement 7 – Restrict Access by Business Need-to-Know
##############################

# Ensure NSGs have deny-all inbound
deny[msg] if {
  some nsg
  azure_nsgs[nsg]
  not nsg_has_deny_all(nsg)
  msg := sprintf("PCI DSS Req 7 Violation: NSG %s missing default deny-all inbound.", [nsg.name])
}

##############################
# Requirement 8 – Identify and Authenticate Users
##############################

# MFA must be enabled
deny[msg] if {
  some acct
  azure_identities[acct]
  not acct.values.mfa_enabled
  msg := sprintf("PCI DSS Req 8 Violation: Identity %s has no MFA enabled.", [acct.name])
}

##############################
# Requirement 9 – Restrict Physical Access
##############################

# Disks must be encrypted
deny[msg] if {
  some disk
  azure_disks[disk]
  not disk.values.encryption.enabled
  msg := sprintf("PCI DSS Req 9 Violation: Disk %s not encrypted with CMK.", [disk.name])
}

##############################
# Requirement 10 – Log and Monitor All Access
##############################

# Resources must have diagnostic logs enabled
deny[msg] if {
  some res
  azure_resources[res]
  not res.values.diagnostics_enabled
  msg := sprintf("PCI DSS Req 10 Violation: Resource %s missing diagnostic logging.", [res.name])
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
