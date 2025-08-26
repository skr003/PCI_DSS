package terraform.azure.cis_pcidss

default deny = []

resources_of_type(t) = r {
  r := input.resource_changes[_]
  r.type == t
  r.change.after != null
}

after(rc) = rc.change.after

# Storage Account: must enforce HTTPS only, TLS1_2, no public access
deny[msg] {
  sa := resources_of_type("azurerm_storage_account")[_]
  a := after(sa)
  not a.enable_https_traffic_only
  msg := sprintf("Storage Account %s must enforce HTTPS only.", [sa.address])
}

deny[msg] {
  sa := resources_of_type("azurerm_storage_account")[_]
  a := after(sa)
  a.allow_blob_public_access
  msg := sprintf("Storage Account %s must disable public blob access.", [sa.address])
}

deny[msg] {
  sa := resources_of_type("azurerm_storage_account")[_]
  a := after(sa)
  a.min_tls_version != "TLS1_2"
  msg := sprintf("Storage Account %s must use TLS1_2.", [sa.address])
}

# Linux VM: disable password auth
deny[msg] {
  vm := resources_of_type("azurerm_linux_virtual_machine")[_]
  a := after(vm)
  not a.disable_password_authentication
  msg := sprintf("VM %s must disable password authentication.", [vm.address])
}

# SQL Server: disable public network and enforce TLS1.2
deny[msg] {
  sql := resources_of_type("azurerm_mssql_server")[_]
  a := after(sql)
  a.public_network_access_enabled
  msg := sprintf("SQL Server %s must disable public network access.", [sql.address])
}

deny[msg] {
  sql := resources_of_type("azurerm_mssql_server")[_]
  a := after(sql)
  a.minimum_tls_version != "1.2"
  msg := sprintf("SQL Server %s must enforce TLS 1.2.", [sql.address])
}
