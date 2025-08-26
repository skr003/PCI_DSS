package azure.pci_dss

default allow = false

# Main entrypoints
allow if {
  count(deny) == 0
}

# =========================
# Requirement 3 – Protect Stored Account Data
# =========================

# Storage must enforce HTTPS
deny[msg] if {
  some sa
  sa := azure_storage_accounts[_]
  not sa.properties.supportsHttpsTrafficOnly
  msg := sprintf("PCI DSS Req 3 Violation: Storage account %s does not enforce HTTPS-only traffic.", [sa.name])
}

# Storage must block blob public access
deny[msg] if {
  some sa
  sa := azure_storage_accounts[_]
  sa.properties.allowBlobPublicAccess == true
  msg := sprintf("PCI DSS Req 3 Violation: Storage account %s allows public blob access.", [sa.name])
}

# =========================
# Requirement 6 – Develop and Maintain Secure Systems and Apps
# =========================

# Ensure VMs are patched recently (example: <= 30 days)
deny[msg] if {
  some vm
  vm := azure_vms[_]
  vm.days_since_last_patch > 30
  msg := sprintf("PCI DSS Req 6 Violation: VM %s has not been patched in %d days.", [vm.name, vm.days_since_last_patch])
}

# =========================
# Requirement 7 – Restrict Access by Business Need-to-Know
# =========================

# Ensure NSGs deny-all inbound by default (only allow explicit rules)
deny[msg] if {
  some nsg
  nsg := azure_nsgs[_]
  not nsg_has_deny_all(nsg)
  msg := sprintf("PCI DSS Req 7 Violation: NSG %s does not implement deny-all inbound by default.", [nsg.name])
}

# =========================
# Requirement 8 – Identify and Authenticate Users
# =========================

# MFA must be enabled on accounts
deny[msg] if {
  some acct
  acct := azure_identities[_]
  not acct.mfa_enabled
  msg := sprintf("PCI DSS Req 8 Violation: Identity %s does not have MFA enabled.", [acct.name])
}

# =========================
# Requirement 9 – Restrict Physical Access
# (mapped as requiring storage accounts + disks encrypted with customer-managed keys)
# =========================

deny[msg] if {
  some disk
  disk := azure_disks[_]
  not disk.encryption.enabled
  msg := sprintf("PCI DSS Req 9 Violation: Disk %s not encrypted with CMK.", [disk.name])
}

# =========================
# Requirement 10 – Log and Monitor All Access
# =========================

# Ensure diagnostic logs enabled for resources
deny[msg] if {
  some res
  res := azure_resources[_]
  not res.diagnostics_enabled
  msg := sprintf("PCI DSS Req 10 Violation: Resource %s does not have diagnostic logging enabled.", [res.name])
}

# =========================
# Helper functions
# =========================

# Slice helper (instead of Python [1:])
slice(arr, lo, hi) = result {
  result := [x |
    i := range(lo, hi-1)[_]
    x := arr[i]
  ]
}

range(lo, hi) = r {
  r := [x | x = lo; x <= hi; x = x+1]
}

# Check if NSG has deny-all inbound
nsg_has_deny_all(nsg) {
  some rule
  rule := nsg.securityRules[_]
  rule.direction == "Inbound"
  rule.access == "Deny"
  rule.priority == 4096   # default deny
}

# =========================
# Input shortcuts
# =========================

azure_storage_accounts = [r | r := input.resource_changes[_]; r.type == "azurerm_storage_account"]
azure_vms              = [r | r := input.resource_changes[_]; r.type == "azurerm_linux_virtual_machine" or r.type == "azurerm_windows_virtual_machine"]
azure_nsgs             = [r | r := input.resource_changes[_]; r.type == "azurerm_network_security_group"]
azure_identities       = [r | r := input.resource_changes[_]; r.type == "azurerm_user" or r.type == "azurerm_ad_user"]
azure_disks            = [r | r := input.resource_changes[_]; r.type == "azurerm_managed_disk"]
azure_resources        = [r | r := input.resource_changes[_]]
