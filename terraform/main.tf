
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=3.50.0"
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
  allow_nested_items_to_be_public = false
  retention_policy {
    enabled = true
    days    = 100
  }
  flow_analytics_configuration {
    network_watcher_flow_analytics_id = azurerm_log_analytics_workspace.law.id
  }
}

# Separate storage account for flow log storage (recommended)
resource "azurerm_storage_account" "logging_sa" {
  name                     = "pciloggingsa" # update to unique name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"
  public_network_access_enabled = false
  https_traffic_only_enabled = true
  https_traffic_only_enabled = false
  shared_access_key_enabled = false
  queue_properties  {
  logging {
        delete                = true
        read                  = true
        write                 = true
        version               = "1.0"
        retention_policy_days = 10
    }
  }
  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }
}

resource "azurerm_private_endpoint" "logging_sa" {
  name                 = "example_private_endpoint"
  location             = azurerm_resource_group.rg.location
  resource_group_name  = azurerm_resource_group.rg.name
  subnet_id            = azurerm_subnet.logging_sa_endpoint.id

  private_service_connection {
    name                           = "logging_sa_endpoint_psc"
    is_manual_connection           = false
    private_connection_resource_id = azurerm_storage_account.logging_sa.id
    subresource_names              = ["blob"]
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

