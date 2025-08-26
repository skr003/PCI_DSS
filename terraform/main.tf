# Provider configuration for Azure
provider "azurerm" {
  features {}
}

# Resource Group (assumed to exist, uncomment and configure if needed)
# resource "azurerm_resource_group" "example" {
#   name     = "rg-compliance-example"
#   location = "West Europe"
# }

# Virtual Network (assumed to exist, uncomment and configure if needed)
# resource "azurerm_virtual_network" "vnet" {
#   name                = "vnet-compliance"
#   address_space       = ["10.0.0.0/16"]
#   location            = azurerm_resource_group.example.location
#   resource_group_name = azurerm_resource_group.example.name
# }

# Subnet for VM and SQL
# resource "azurerm_subnet" "subnet" {
#   name                 = "subnet-compliance"
#   resource_group_name  = azurerm_resource_group.example.name
#   virtual_network_name = azurerm_virtual_network.vnet.name
#   address_prefixes     = ["10.0.1.0/24"]
# }

# Storage Account with encryption and private endpoint
resource "azurerm_storage_account" "storage" {
  name                     = "stcompliance2025"
  resource_group_name      = "rg-compliance-example" # Replace with your resource group
  location                 = "West Europe"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  min_tls_version          = "TLS1_2"

  # Enable encryption for data at rest
  enable_https_traffic_only = true

  # Network rules to restrict public access
  network_rules {
    default_action             = "Deny"
    ip_rules                   = []
    virtual_network_subnet_ids = ["/subscriptions/<subscription-id>/resourceGroups/rg-compliance-example/providers/Microsoft.Network/virtualNetworks/vnet-compliance/subnets/subnet-compliance"] # Replace with subnet ID
    bypass                     = ["AzureServices"]
  }

  # Tags for compliance tracking
  tags = {
    environment = "production"
    compliance  = "pci-dss"
  }
}

# Private Endpoint for Storage Account
resource "azurerm_private_endpoint" "storage_pe" {
  name                = "pe-storage-compliance"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.subnet.id

  private_service_connection {
    name                           = "psc-storage-compliance"
    private_connection_resource_id = azurerm_storage_account.storage.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "private-dns-zone-group"
    private_dns_zone_ids = ["/subscriptions/<subscription-id>/resourceGroups/rg-compliance-example/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"] # Replace with DNS zone ID
  }
}

# Virtual Machine with encryption and managed identity
resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "vm-compliance"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  network_interface_ids = [azurerm_network_interface.vm_nic.id]
  size                  = "Standard_DS1_v2"

  admin_username = "adminuser"
  admin_password = "ComplexPassword123!" # Replace with secure password or use SSH key

  # Disable password authentication for security
  disable_password_authentication = false # Set to true and use ssh_key if preferred

  # OS disk encryption
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_encryption_set_id = azurerm_disk_encryption_set.des.id
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  # Managed Identity for secure access
  identity {
    type = "SystemAssigned"
  }

  tags = {
    environment = "production"
    compliance  = "pci-dss"
  }
}

# Network Interface for VM
resource "azurerm_network_interface" "vm_nic" {
  name                = "nic-vm-compliance"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

# Disk Encryption Set for VM
resource "azurerm_disk_encryption_set" "des" {
  name                = "des-compliance"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  key_vault_key_id    = azurerm_key_vault_key.key.id

  identity {
    type = "SystemAssigned"
  }
}

# Key Vault for encryption keys
resource "azurerm_key_vault" "kv" {
  name                        = "kv-compliance-2025"
  location                    = azurerm_resource_group.example.location
  resource_group_name         = azurerm_resource_group.example.name
  enabled_for_disk_encryption = true
  tenant_id                   = "<tenant-id>" # Replace with your tenant ID
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true

  sku_name = "standard"

  access_policy {
    tenant_id = "<tenant-id>" # Replace with your tenant ID
    object_id = "<object-id>" # Replace with your object ID (e.g., from managed identity)

    key_permissions = [
      "Get", "WrapKey", "UnwrapKey", "Create", "Delete", "Purge"
    ]

    secret_permissions = [
      "Get", "Set", "Delete", "Purge"
    ]
  }
}

# Key Vault Key for encryption
resource "azurerm_key_vault_key" "key" {
  name         = "key-compliance"
  key_vault_id = azurerm_key_vault.kv.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["encrypt", "decrypt", "wrapKey", "unwrapKey"]

  depends_on = [azurerm_key_vault.kv]
}

# Azure SQL Database with auditing and TLS
resource "azurerm_mssql_server" "sql" {
  name                         = "sql-compliance-2025"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "ComplexPassword123!" # Replace with secure password

  # Enforce TLS and disable public access
  public_network_access_enabled = false
  tls_version                   = "1.2"

  # Tags for compliance tracking
  tags = {
    environment = "production"
    compliance  = "pci-dss"
  }
}

resource "azurerm_mssql_database" "db" {
  name           = "db-compliance"
  server_id      = azurerm_mssql_server.sql.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  license_type   = "LicenseIncluded"
  max_size_gb    = 5
  sku_name       = "S0"

  # Enable auditing for compliance
  threat_detection_policy {
    state                      = "Enabled"
    retention_days             = 30
    disabled_alerts            = []
    email_account_admins       = true
    email_addresses            = ["admin@domain.com"] # Replace with your email
  }

  # Transparent Data Encryption (TDE)
  transparent_data_encryption_enabled = true
}

# Private Endpoint for SQL Server
resource "azurerm_private_endpoint" "sql_pe" {
  name                = "pe-sql-compliance"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  subnet_id           = azurerm_subnet.subnet.id

  private_service_connection {
    name                           = "psc-sql-compliance"
    private_connection_resource_id = azurerm_mssql_server.sql.id
    subresource_names              = ["sqlServer"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "private-dns-zone-group-sql"
    private_dns_zone_ids = ["/subscriptions/<subscription-id>/resourceGroups/rg-compliance-example/providers/Microsoft.Network/privateDnsZones/privatelink.database.windows.net"] # Replace with DNS zone ID
  }
}
