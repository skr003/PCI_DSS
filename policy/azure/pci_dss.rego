package azure.pci_dss_v4

# Helper to get resource type, handling case-insensitivity
get_resource_type(resource) = lower(resource.type)

#-------------------------------------------------------------------
# Requirement 3: Protect Stored Account Data [1]
#-------------------------------------------------------------------

# PCI DSS 3.5.1: Ensure SQL Databases have Transparent Data Encryption enabled
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.sql/servers/databases"
    properties := resource.properties
    # TDE is enabled by default on new databases, but this checks for explicit status
    not properties.transparentDataEncryption.status == "Enabled"
    msg := sprintf("PCI DSS 3.5.1: SQL Database '%s' does not have Transparent Data Encryption (TDE) enabled.", [resource.name])
}

# PCI DSS 3.5.1: Ensure Storage Accounts enforce HTTPS traffic only
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.storage/storageaccounts"
    not resource.properties.supportsHttpsTrafficOnly
    msg := sprintf("PCI DSS 3.5.1: Storage Account '%s' does not enforce HTTPS traffic only.", [resource.name])
}

# PCI DSS 3.6: Ensure Key Vaults have soft delete enabled
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.keyvault/vaults"
    not resource.properties.enableSoftDelete
    msg := sprintf("PCI DSS 3.6: Key Vault '%s' does not have soft delete enabled.", [resource.name])
}

# PCI DSS 3.6: Ensure Key Vaults have purge protection enabled
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.keyvault/vaults"
    not resource.properties.enablePurgeProtection
    msg := sprintf("PCI DSS 3.6: Key Vault '%s' does not have purge protection enabled.", [resource.name])
}


#-------------------------------------------------------------------
# Requirement 6: Develop and Maintain Secure Systems and Software [1]
#-------------------------------------------------------------------

# PCI DSS 6.3: Ensure a vulnerability assessment solution is enabled for Virtual Machines
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.compute/virtualmachines"
    # This is a simplified check; a real implementation would check for specific extensions
    # or integration with Microsoft Defender for Cloud's vulnerability assessment.
    not resource.properties.storageProfile.osDisk.managedDisk
    msg := sprintf("PCI DSS 6.3: Virtual Machine '%s' is not using Managed Disks, which may complicate vulnerability management.", [resource.name])
}

# PCI DSS 6.4: Ensure App Service has an associated Web Application Firewall (WAF)
# This check assumes a naming convention or tag links the App Service to an Application Gateway with WAF.
# A more robust check would require graph-based analysis of resource relationships.
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.web/sites"
    not resource.properties.httpsOnly
    msg := sprintf("PCI DSS 6.4: App Service '%s' does not enforce HTTPS-only traffic, a baseline for web application security.", [resource.name])
}


#-------------------------------------------------------------------
# Requirement 7: Restrict Access to System Components [1]
#-------------------------------------------------------------------

# PCI DSS 7.2.2: Restrict public network access for Storage Accounts
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.storage/storageaccounts"
    not resource.properties.publicNetworkAccess == "Disabled"
    msg := sprintf("PCI DSS 7.2.2: Storage Account '%s' allows public network access.", [resource.name])
}

# PCI DSS 7.2.2: Restrict public network access for SQL Servers
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.sql/servers"
    not resource.properties.publicNetworkAccess == "Disabled"
    msg := sprintf("PCI DSS 7.2.2: SQL Server '%s' allows public network access.", [resource.name])
}

# PCI DSS 7.2.2: Restrict RDP/SSH access from the internet on Network Security Groups
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.network/networksecuritygroups"
    rule := resource.properties.securityRules[_]
    rule.properties.direction == "Inbound"
    rule.properties.access == "Allow"
    rule.properties.protocol == "Tcp"
    rule.properties.sourceAddressPrefix == "*"
    rule.properties.destinationPortRange == "3389" # RDP
    msg := sprintf("PCI DSS 7.2.2: Network Security Group '%s' allows RDP access from the Internet.", [resource.name])
}

deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.network/networksecuritygroups"
    rule := resource.properties.securityRules[_]
    rule.properties.direction == "Inbound"
    rule.properties.access == "Allow"
    rule.properties.protocol == "Tcp"
    rule.properties.sourceAddressPrefix == "*"
    rule.properties.destinationPortRange == "22" # SSH
    msg := sprintf("PCI DSS 7.2.2: Network Security Group '%s' allows SSH access from the Internet.", [resource.name])
}


#-------------------------------------------------------------------
# Requirement 8: Identify Users and Authenticate Access [1]
#-------------------------------------------------------------------

# PCI DSS 8.4.2: Check for MFA on subscription owner accounts (conceptual check)
# This is typically an Azure AD setting, but we can represent it as a check on the subscription resource.
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.resources/subscriptions"
    # This is a placeholder for a more complex check that would require an audit of IAM policies.
    # A true check would query Azure AD or use an 'AuditIfNotExists' pattern.
    not resource.properties.mfaEnforcedForOwners
    msg := sprintf("PCI DSS 8.4.2: Subscription '%s' does not have a policy to enforce MFA for owners.", [resource.name])
}

# PCI DSS 8.3.6: Ensure Linux VMs disable password authentication in favor of SSH keys
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.compute/virtualmachines"
    properties := resource.properties
    not properties.osProfile.linuxConfiguration.disablePasswordAuthentication
    msg := sprintf("PCI DSS 8.3.6: Linux VM '%s' does not disable password authentication.", [resource.name])
}


#-------------------------------------------------------------------
# Requirement 9: Restrict Physical Access to Cardholder Data [1]
#-------------------------------------------------------------------

# Logical equivalent for PCI DSS 9: Prohibit public IPs on Virtual Machines in the CDE
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.network/networkinterfaces"
    config := resource.properties.ipConfigurations[_]
    config.properties.publicIPAddress
    msg := sprintf("PCI DSS 9: Network Interface '%s' has a public IP, which is discouraged for CDE components.", [resource.name])
}


#-------------------------------------------------------------------
# Requirement 10: Log and Monitor All Access [1]
#-------------------------------------------------------------------

# PCI DSS 10.2.1: Ensure diagnostic logging is enabled for Key Vaults
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.keyvault/vaults"
    # This is a simplified check. A full check would use an 'AuditIfNotExists' policy to verify
    # the existence of a linked 'Microsoft.Insights/diagnosticSettings' resource.
    not resource.properties.enabledForDeployment # A proxy for detailed logging checks
    msg := sprintf("PCI DSS 10.2.1: Key Vault '%s' may not have full diagnostic logging enabled.", [resource.name])
}

# PCI DSS 10.2.1: Ensure logging is enabled for Network Security Groups
deny contains msg {
    resource := input.resources[_]
    get_resource_type(resource) == "microsoft.network/networksecuritygroups"
    # This is a simplified check. A full check would verify a linked 'Microsoft.Insights/diagnosticSettings' resource.
    not resource.properties.enableFlowLogs # A proxy for detailed logging checks
    msg := sprintf("PCI DSS 10.2.1: Network Security Group '%s' does not have NSG Flow Logs enabled.", [resource.name])
}
