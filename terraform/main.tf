terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.50"
    }
  }
  required_version = ">= 1.3.0"
}

provider "azurerm" {
  features {}
}

# -----------------------
# Variables (tweak before use)
# -----------------------
variable "location" {
  type    = string
  default = "East US"
}

variable "rg_name" {
  type    = string
  default = "pci-compliance-rg"
}

# Set to a secure admin public key path
variable "admin_ssh_pubkey_path" {
  type    = string
  default = "~/.ssh/id_rsa.pub"
}

# If you want to restrict SSH to a single CIDR (recommended), set here.
# By default we restrict to the VNet internal prefix (no internet-wide 0.0.0.0/0).
variable "ssh_source_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

# -----------------------
# Resource Group
# -----------------------
resource "azurerm_resource_group" "rg" {
  name     = var.rg_name
  location = var.location
}

# -----------------------
# Log Analytics Workspace (central place for logs)
# -----------------------
resource "azurerm_log_analytics_workspace" "law" {
  name                = "${var.rg_name}-law"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

# -----------------------
# Network Watcher (required for flow logs)
# -----------------------
resource "azurerm_network_watcher" "nw" {
  name                = "${var.rg_name}-nw"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  retention_policy {
  enabled = true
  days    = <90 or greater>
}

# -----------------------
# Virtual Network & Subnet
# -----------------------
resource "azurerm_virtual_network" "vnet" {
  name                = "${var.rg_name}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "pci-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# -----------------------
# Network Security Group (with descriptions)
# -----------------------
resource "azurerm_network_security_group" "nsg" {
  name                = "${var.rg_name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "Allow-SSH-From-Internal"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.ssh_source_cidr
    destination_address_prefix = "*"
    description                = "Allow SSH from internal management CIDR only (no 0.0.0.0/0)"
  }

  security_rule {
    name                       = "Deny-Internet-All"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
    description                = "Default deny inbound from Internet"
  }
}

# Associate NSG to subnet
resource "azurerm_subnet_network_security_group_association" "subnet_nsg_assoc" {
  subnet_id                 = azurerm_subnet.subnet.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# -----------------------
# Flow Logs for NSG (network watcher)
# -----------------------
resource "azurerm_network_watcher_flow_log" "nsg_flow_log" {
  network_watcher_name        = azurerm_network_watcher.nw.name
  resource_group_name         = azurerm_resource_group.rg.name
  location                    = azurerm_resource_group.rg.location
  network_security_group_id   = azurerm_network_security_group.nsg.id
  storage_account_id          = azurerm_storage_account.logging_sa.id
  enabled                     = true
  retention_policy {
    enabled = true
    days    = 30
  }
  flow_analytics_configuration {
    network_watcher_flow_analytics_id = azurerm_log_analytics_workspace.law.id
  }
}

# -----------------------
# Storage Account (hardened)
# -----------------------
resource "azurerm_storage_account" "storage" {
  name                     = "pcidssstoragedemo" # must be globally unique; change if necessary
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "GRS"        # CKV_AZURE_206 remediation (change to ZRS if you prefer)
  min_tls_version          = "TLS1_2"
  allow_blob_public_access = false        # CKV_AZURE_190 / CKV_AZURE_59 remediation
  public_network_access_enabled = false  # further restrict public network access
  enable_https_traffic_only = true
  is_hns_enabled           = false
  local_user_enabled       = false
  queue_properties  {
    logging {
        delete                = true
        read                  = true
        write                 = true
        version               = "1.0"
        retention_policy_days = 10
    }
  }
  # advanced threat protection & encryption are provided by platform by default; add CMK if required.
}

# Separate storage account for flow log storage (recommended)
resource "azurerm_storage_account" "logging_sa" {
  name                     = "pciloggingsa" # update to unique name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
  allow_blob_public_access = false
  public_network_access_enabled = false
  enable_https_traffic_only = true
}

# -----------------------
# Blob soft-delete (CKV2_AZURE_38)
# -----------------------
resource "azurerm_storage_account_blob_properties" "blob_props" {
  storage_account_id = azurerm_storage_account.storage.id

  delete_retention_policy {
    days = 30
  }

  # Optional: versioning, CORS, etc.
  is_versioning_enabled = true
}

# -----------------------
# Diagnostic settings - Storage Queue logging (CKV_AZURE_33)
# -----------------------
resource "azurerm_monitor_diagnostic_setting" "storage_diagnostics" {
  name                       = "${var.rg_name}-storage-diag"
  target_resource_id         = azurerm_storage_account.storage.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  # Storage logs
  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
  # Additional storage metrics/events
  metric {
    category = "Transaction"
    enabled  = true
    retention_policy {
      enabled = true
      days    = 30
    }
  }
}

# -----------------------
# Public IP + NIC for VM (minimal)
# -----------------------
resource "azurerm_public_ip" "pip" {
  name                = "${var.rg_name}-pip"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Dynamic"
  sku                 = "Basic"
}

resource "azurerm_network_interface" "nic" {
  name                = "${var.rg_name}-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

# -----------------------
# Linux VM (no extensions) -> CKV_AZURE_50 remediation: we simply do not create extensions
# -----------------------
resource "azurerm_linux_virtual_machine" "vm" {
  name                            = "${var.rg_name}-vm"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  size                            = "Standard_B1s"
  admin_username                  = "azureuser"
  network_interface_ids           = [azurerm_network_interface.nic.id]
  disable_password_authentication = true
  encryption_at_host_enabled      = true          # addresses VM encryption checks (CKV2 variants)

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  admin_ssh_key {
    username   = "azureuser"
    public_key = file(var.admin_ssh_pubkey_path)
  }

  # Note: Do NOT add 'extension' blocks here. Many checkov rules (CKV_AZURE_50)
  # flag extensions. If you must use extensions, ensure justified and consider suppressing specific checks.
}

# VM Diagnostics -> send metrics/logs to Log Analytics (prevents auditing gaps)
resource "azurerm_monitor_diagnostic_setting" "vm_diagnostics" {
  name                       = "${var.rg_name}-vm-diag"
  target_resource_id         = azurerm_linux_virtual_machine.vm.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  metric {
    category = "AllMetrics"
    enabled  = true
    retention_policy {
      enabled = true
      days    = 30
    }
  }

  log {
    category = "Syslog"
    enabled  = true
  }
  log {
    category = "LinuxSyslog"
    enabled  = true
  }
}

# -----------------------
# IAM Example - RBAC Role Assignment (least privilege) - replace principal_id
# -----------------------
data "azurerm_subscription" "primary" {}

resource "azurerm_role_assignment" "example_reader" {
  scope                = azurerm_resource_group.rg.id
  role_definition_name = "Reader"
  principal_id         = "00000000-0000-0000-0000-000000000000" # Replace with real AAD object id
}

# -----------------------
# SQL Server + Database (hardened)
# -----------------------
resource "azurerm_mssql_server" "sqlserver" {
  name                         = "pcisqlserverdemo" # must be globally unique in rg scope
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"
  administrator_login          = "sqladminuser"
  administrator_login_password = "StrongP@ssword123!"

  public_network_access_enabled = false   # CKV_AZURE_113 remediation
  minimum_tls_version           = "1.2"  # CKV_AZURE_52 remediation
}

resource "azurerm_mssql_database" "sqldb" {
  name           = "pcidb"
  server_id      = azurerm_mssql_server.sqlserver.id
  sku_name       = "S0"
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  max_size_gb    = 10
  zone_redundant = true     # CKV_AZURE_229 remediation (zone redundancy)

  ledger_enabled = true     # CKV_AZURE_224 remediation (when DB type supports ledger)
}

# SQL Auditing -> send to Log Analytics
resource "azurerm_mssql_server_extended_auditing_policy" "sql_audit" {
  server_id                        = azurerm_mssql_server.sqlserver.id
  storage_endpoint                  = azurerm_storage_account.logging_sa.primary_blob_endpoint
  storage_account_access_key        = azurerm_storage_account.logging_sa.primary_access_key
  retention_in_days                 = 30
  audit_actions_and_groups          = ["BATCH_COMPLETED_GROUP", "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP", "FAILED_DATABASE_AUTHENTICATION_GROUP"]
  is_azure_monitor_target_enabled   = true
  log_analytics_workspace_id        = azurerm_log_analytics_workspace.law.id
}

# -----------------------
# Outputs (useful for troubleshooting)
# -----------------------
output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "storage_account" {
  value = azurerm_storage_account.storage.name
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.vm.name
}

output "sql_server" {
  value = azurerm_mssql_server.sqlserver.name
}
