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
# Resource Group
# -----------------------
resource "azurerm_resource_group" "rg" {
  name     = "pci-compliance-rg"
  location = "East US"
}

# -----------------------
# Log Analytics Workspace
# -----------------------
resource "azurerm_log_analytics_workspace" "law" {
  name                = "pci-law"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# -----------------------
# Storage Account
# -----------------------
resource "azurerm_storage_account" "storage" {
  name                     = "pcidssstoragedemo123"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "GRS"                     # Fix CKV_AZURE_206
  min_tls_version          = "TLS1_2"
  allow_blob_public_access = false                     # Fix CKV_AZURE_190 / 59
  public_network_access_enabled = false                # Extra hardening
}

# Enable soft delete for blobs (Fix CKV2_AZURE_38)
resource "azurerm_storage_account_blob_properties" "soft_delete" {
  storage_account_id = azurerm_storage_account.storage.id

  delete_retention_policy {
    days = 30
  }
}

# Diagnostic settings for Queue logging (Fix CKV_AZURE_33)
resource "azurerm_monitor_diagnostic_setting" "storage_logging" {
  name                       = "storagelogging"
  target_resource_id         = azurerm_storage_account.storage.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
    enabled  = true
  }
}

# -----------------------
# Virtual Network & Subnet
# -----------------------
resource "azurerm_virtual_network" "vnet" {
  name                = "pci-vnet"
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
# Network Security Group
# -----------------------
resource "azurerm_network_security_group" "nsg" {
  name                = "pci-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# -----------------------
# Public IP + NIC
# -----------------------
resource "azurerm_public_ip" "pip" {
  name                = "pci-pip"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Dynamic"
}

resource "azurerm_network_interface" "nic" {
  name                = "pci-nic"
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
# Linux VM (no extensions) → Fix CKV_AZURE_50
# -----------------------
resource "azurerm_linux_virtual_machine" "vm" {
  name                = "pci-vm"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_B1s"
  admin_username      = "azureuser"
  network_interface_ids = [
    azurerm_network_interface.nic.id,
  ]

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

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
}

# -----------------------
# IAM Role Assignment
# -----------------------
data "azurerm_subscription" "primary" {}

resource "azurerm_role_assignment" "iam" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Reader"
  principal_id         = "00000000-0000-0000-0000-000000000000" # Replace with AAD Object ID
}

# -----------------------
# SQL Database (Fix CKV_AZURE_224 + CKV_AZURE_229)
# -----------------------
resource "azurerm_mssql_server" "sqlserver" {
  name                         = "pcisqlserverdemo123"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"
  administrator_login          = "sqladminuser"
  administrator_login_password = "StrongP@ssword123!"
}

resource "azurerm_mssql_database" "sqldb" {
  name           = "pcidb"
  server_id      = azurerm_mssql_server.sqlserver.id
  sku_name       = "S0"
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  max_size_gb    = 10
  zone_redundant = true        # Fix CKV_AZURE_229

  ledger_enabled = true        # Fix CKV_AZURE_224
}
