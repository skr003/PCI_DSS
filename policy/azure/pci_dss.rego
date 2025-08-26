package pci_dss

# PCI DSS v4.0 checks (requirements 3,6,7,8,9,10) for Azure (Terraform plan/state style input).
# Input expectation:
#  - input.resource_changes : array of resource-change objects (Terraform "show -json" plan)
#    each element: { "type": "azurerm_storage_account"|"azurerm_virtual_machine"|..., "name": "...", "change": { "after": {...} } }
#
# This policy tries common field names used by azurerm provider. If your JSON uses a different path,
# adapt the helper functions below or pre-normalize the JSON.

########################
# Entry points
########################
default allow = false

deny[msg] {
  v := violations[_]
  msg := v
}

allow if {
  count(violations) == 0
}

violations[entry] {
  entry := req3_violations[_]
}
violations[entry] {
  entry := req6_violations[_]
}
violations[entry] {
  entry := req7_violations[_]
}
violations[entry] {
  entry := req8_violations[_]
}
violations[entry] {
  entry := req9_violations[_]
}
violations[entry] {
  entry := req10_violations[_]
}

########################
# Helpers
########################

# Iterate resources in input.resource_changes (Terraform plan format)
resource_changes := [rc | rc := input.resource_changes[_]]

# get_after(rc) -> safe after obj (handles plan where change/after might be nested)
get_after(rc) = after {
  after := rc.change.after
}

# safe getter with default: returns null if not present
get_in(obj, path) = val {
  parts := split(path, ".")
  val := walk_get(obj, parts)
}

walk_get(obj, parts) = out {
  count(parts) == 0
  out := obj
} else = out {
  count(parts) > 0
  p := parts[0]
  rest := parts[1:]
  is_object(obj)
  obj[p] != null
  out := walk_get(obj[p], rest)
}

is_object(x) {
  x != null
  not is_scalar(x)
}

is_scalar(x) {
  x == null
} else = true {
  type_of(x) == "string" 
} else = true {
  type_of(x) == "number"
} else = true {
  type_of(x) == "boolean"
}

type_of(x) = t {
  t := sprintf("%v", [x])     # cheap fallback; used only to detect scalars above
}

# convenience: check resource type
is_storage(rc) { rc.type == "azurerm_storage_account" }
is_vm(rc) { rc.type == "azurerm_virtual_machine" ; rc.type == "azurerm_linux_virtual_machine" ; rc.type == "azurerm_windows_virtual_machine" }

# helper to extract role assignments (if present in plan): resource type azurerm_role_assignment
role_assignments := [rc | rc := resource_changes[_]; rc.type == "azurerm_role_assignment"]

########################
# Requirement 3 — Protect Stored Account Data
# (PCI DSS Req 3: minimize storage, render PAN unreadable, don't store SAD after auth, encrypt at rest, key management)
# Practical automated checks for Azure:
#  - Storage accounts must not allow public blob access
#  - Storage accounts must enforce HTTPS only
#  - Min TLS version should be >= TLS1_2 (proxy for strong crypto)
#  - Storage accounts storing account data must have encryption & key protection indicated
########################

req3_violations[v] {
  rc := resource_changes[_]
  rc.type == "azurerm_storage_account"
  after := get_after(rc)

  # 1) Public blob access allowed -> fail
  val := get_in(after, "allow_blob_public_access")
  val == true
  v := {
    "req": "3",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "3.2/3.5",
    "msg": sprintf("Storage account '%s' allows public blob access (allow_blob_public_access=true).", [rc.name])
  }
}

req3_violations[v] {
  rc := resource_changes[_]
  rc.type == "azurerm_storage_account"
  after := get_after(rc)

  # 2) HTTPS enforcement missing -> fail
  val1 := get_in(after, "enable_https_traffic_only")
  # older providers may use "enable_https_traffic_only" or nested properties
  (val1 == false)                                 # explicit false
  v := {
    "req": "3",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "3.5",
    "msg": sprintf("Storage account '%s' does not enforce HTTPS only (enable_https_traffic_only=false).", [rc.name])
  }
}

req3_violations[v] {
  rc := resource_changes[_]
  rc.type == "azurerm_storage_account"
  after := get_after(rc)

  # 3) TLS minimum version check (should be TLS1_2 or higher)
  tls := get_in(after, "min_tls_version")
  tls == "TLS1_0"  # fail if TLS1_0 (some providers use "TLS1_0"/"TLS1_2")
  v := {
    "req": "3",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "3.4",
    "msg": sprintf("Storage account '%s' allows TLS1.0 (min_tls_version=%s). Require TLS1.2+.", [rc.name, tls])
  }
}

req3_violations[v] {
  # 4) Key management proxy: check if 'encryption' indicates a customer-managed key not present/disabled
  rc := resource_changes[_]
  rc.type == "azurerm_storage_account"
  after := get_after(rc)

  # Many TF providers expose "encryption" or "identity" + "key_vault_key_id"
  kv := get_in(after, "encryption.key_vault_key_id")
  # if storage is used to store account data but there is no CMK evidence, flag (this is a heuristic)
  stores := get_in(after, "tags.stores_account_data")  # optional tag used by infra to indicate CHD
  stores == "true"
  kv == null
  v := {
    "req": "3",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "3.6/3.7",
    "msg": sprintf("Storage account '%s' appears to store account data (tag 'stores_account_data'='true') but no customer-managed key (key_vault_key_id) is configured.", [rc.name])
  }
}

########################
# Requirement 6 — Develop and Maintain Secure Systems and Software
# (PCI DSS Req 6: secure development, patching, remove test data)
# Automated checks:
#  - VM tags or extensions indicating presence of test data -> fail
#  - VM must have Update Management / automatic patching extensions (heuristic: presence of 'azureautomation' or 'vm_extension' for update management)
#  - Code repos & apps: we check presence of CodeRepo resources is out-of-scope here; focus on VMs.
########################

req6_violations[v] {
  rc := resource_changes[_]
  rc.type == "azurerm_virtual_machine"  # generic VM
  after := get_after(rc)
  tags_have := get_in(after, "tags.contains_test_data")
  tags_have == "true"
  v := {
    "req": "6",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "6.5.6",
    "msg": sprintf("VM '%s' is marked as containing test data/accounts (tags.contains_test_data=true). Remove test data from production systems.", [rc.name])
  }
}

req6_violations[v] {
  # patching: heuristic: require 'patch_management' tag or an update management extension
  rc := resource_changes[_]
  rc.type == "azurerm_virtual_machine"
  after := get_after(rc)

  tag_patch := get_in(after, "tags.patch_policy")
  ext_present := endswith(tostring(get_in(after, "extension_names")), "UpdateManagement")  # heuristic
  not tag_patch
  not ext_present
  v := {
    "req": "6",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "6.1/6.2",
    "msg": sprintf("VM '%s' has no visible patch management configuration (no tags.patch_policy and no UpdateManagement extension).", [rc.name])
  }
}

# helper substring check used above (simple)
endswith(s, suffix) {
  s != null
  endswith := contains(s, suffix)
}

contains(s, sub) {
  s != null
  sub != ""
  indexof(s, sub) >= 0
}

########################
# Requirement 7 — Restrict Access by Business Need to Know
# (PCI DSS Req 7: least privilege, deny-by-default)
# Automated checks:
#  - Role assignments granting 'Owner' to principals that are not clearly "service principal" (heuristic)
#  - Network Security Group rules allowing inbound 0.0.0.0/0 to sensitive ports (RDP/SSH) -> fail
########################

req7_violations[v] {
  # Owner role assigned widely
  ra := role_assignments[_]
  after := get_after(ra)
  # role definition name may appear as role_definition_name or role_definition_id
  role_name := get_in(after, "role_definition_name")
  # sometimes it's an id — fallback simple string check for '/roleDefinitions/' and 'Owner'
  role_name == "Owner"
  # principal_type heuristics: if principal_type == "User" or "Group" (not "ServicePrincipal") then warn
  ptype := get_in(after, "principal_type")
  ptype == "User"
  v := {
    "req": "7",
    "id": sprintf("%s.%s", [ra.type, ra.name]),
    "control": "7.3",
    "msg": sprintf("Role assignment '%s' grants Owner to principal type User. Avoid Owner-level access; use least privilege.", [ra.name])
  }
}

req7_violations[v] {
  # NSG rule allowing RDP/SSH from any source
  rc := resource_changes[_]
  rc.type == "azurerm_network_security_rule"
  after := get_after(rc)
  after.direction == "Inbound"
  after.access == "Allow"
  after.source_address_prefix == "0.0.0.0/0"
  (after.destination_port_range == "22" or after.destination_port_range == "3389" or contains(after.destination_port_range, "22") or contains(after.destination_port_range, "3389"))
  v := {
    "req": "7",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "7.1/7.2",
    "msg": sprintf("NSG rule '%s' allows inbound %s from 0.0.0.0/0. Restrict administrative access to authorized source ranges or jump hosts.", [rc.name, after.destination_port_range])
  }
}

########################
# Requirement 8 — Identify Users and Authenticate
# (PCI DSS Req 8: unique IDs, MFA for non-console admin into CDE and all access into CDE, remote access MFA)
# Automated checks (proxies):
#  - Check existence of Azure AD Conditional Access or MFA conditional policy resource (heuristic)
#  - Check that role assignments do not indicate shared credentials tags
########################

req8_violations[v] {
  # MFA for admin into CDE: we can't read Azure AD CA policies from tfplan unless present, so check for existence of a resource indicating MFA enforcement
  found := [rc | rc := resource_changes[_]; rc.type == "azuread_conditional_access_policy" || rc.type == "azuread_authentication_method" ]
  count(found) == 0
  v := {
    "req": "8",
    "id": "identity_control_missing",
    "control": "8.4",
    "msg": "No Azure AD Conditional Access/MFA resources found in plan. Ensure MFA is enforced for all administrative and CDE access (MFA/Conditional Access)."
  }
}

req8_violations[v] {
  # Shared auth factor tagging heuristic: check if any principal is tagged/shared_auth_factors
  ra := role_assignments[_]
  after := get_after(ra)
  tags := get_in(after, "tags.shared_auth_factors")
  tags == "true"
  v := {
    "req": "8",
    "id": sprintf("%s.%s", [ra.type, ra.name]),
    "control": "8.3.11",
    "msg": sprintf("Role assignment '%s' tagged 'shared_auth_factors=true' indicates shared authentication factors; disallow shared credentials.", [ra.name])
  }
}

########################
# Requirement 9 — Restrict Physical Access
# (PCI DSS Req 9: physical access controls and monitoring)
# Automated checks are limited in cloud; we check for some record/monitoring resources (e.g., diagnostic settings for Key Vault / Storage / NSG flow logs) as proxies.
########################

req9_violations[v] {
  # If key vaults exist (customer-managed keys), ensure diagnostic settings enabled (proxy for monitoring)
  rc := resource_changes[_]
  rc.type == "azurerm_key_vault"
  after := get_after(rc)
  diag := get_in(after, "diagnostic_settings_count")
  diag == 0
  v := {
    "req": "9",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "9.3",
    "msg": sprintf("Key Vault '%s' has no diagnostic settings configured; ensure physical/logged access and monitoring for sensitive key material.", [rc.name])
  }
}

req9_violations[v] {
  # If storage account used for CHD, ensure blob soft-delete/immutable policies (proxy for physical/media protection)
  rc := resource_changes[_]
  rc.type == "azurerm_storage_account"
  after := get_after(rc)
  stores := get_in(after, "tags.stores_account_data")
  stores == "true"
  imm := get_in(after, "delete_retention_policy.days")
  imm == null
  v := {
    "req": "9",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "9.5",
    "msg": sprintf("Storage account '%s' stores account data but has no delete_retention_policy configured; enable retention/immutability for records.", [rc.name])
  }
}

########################
# Requirement 10 — Log and Monitor All Access
# (PCI DSS Req 10: enable logging, protect logs, retain, review)
# Automated checks:
#  - Diagnostic settings / Log Analytics must be present for VMs and Storage Accounts
#  - Diagnostic settings should stream to a protected storage/LA/workspace
########################

req10_violations[v] {
  # Storage without diagnostic settings
  rc := resource_changes[_]
  rc.type == "azurerm_storage_account"
  after := get_after(rc)
  diag := get_in(after, "diagnostic_settings_count")
  (diag == null) or (diag == 0)
  v := {
    "req": "10",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "10.2",
    "msg": sprintf("Storage account '%s' has no diagnostic settings configured; enable logging to Log Analytics / Event Hub / protected storage.", [rc.name])
  }
}

req10_violations[v] {
  # VM without diagnostic extension or diagnostic settings
  rc := resource_changes[_]
  rc.type == "azurerm_virtual_machine"
  after := get_after(rc)
  # check for boot_diagnostics.enabled or vm extension presence for diagnostics
  bd := get_in(after, "diagnostics_profile.boot_diagnostics.enabled")
  has_extension := contains(tostring(get_in(after, "extension_names")), "AzureMonitor")  # heuristic
  (bd != true)
  not has_extension
  v := {
    "req": "10",
    "id": sprintf("%s.%s", [rc.type, rc.name]),
    "control": "10.2",
    "msg": sprintf("VM '%s' has no boot diagnostics or monitoring extension visible; enable diagnostic logs and forward to protected SIEM/Log Analytics.", [rc.name])
  }
}

req10_violations[v] {
  # Logs not protected: diagnostic sink should not be the same storage account that is publicly accessible (heuristic)
  # Check diagnostic settings destination name (if present)
  ds := [rc | rc := resource_changes[_]; rc.type == "azurerm_monitor_diagnostic_setting"]
  some i
  ds[i]
  ds_rc := ds[i]
  after := get_after(ds_rc)
  # destination could be storage_account_id; check that that storage account is not public
  sa := get_in(after, "storage_account_id")
  sa != null
  # find referenced storage account resource_change
  target := [x | x := resource_changes[_]; x.type == "azurerm_storage_account"; contains(tostring(x.address), sa) ]
  count(target) > 0
  t := target[0]
  t_after := get_after(t)
  pub := get_in(t_after, "allow_blob_public_access")
  pub == true
  v := {
    "req": "10",
    "id": sprintf("diag.%s", [ds_rc.name]),
    "control": "10.3",
    "msg": sprintf("Diagnostic setting '%s' sends logs to storage account that allows public blob access. Use protected sink.", [ds_rc.name])
  }
}
