package azure.pci_dss

import future.keywords.if

# Default states
default allow = false
default deny = false

# PCI DSS Requirement 3: Protect Stored Account Data
allow if {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    resource.properties.encryption.services.blob.enabled
    resource.properties.encryption.services.file.enabled
    resource.properties.encryption.keySource == "Microsoft.Keyvault"
    resource.properties.publicNetworkAccess == "Disabled"
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    not resource.properties.encryption.services.blob.enabled
    msg := sprintf("PCI DSS 3.5 violation: Storage account '%s' does not have blob encryption enabled.", [resource.name])
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    not resource.properties.encryption.services.file.enabled
    msg := sprintf("PCI DSS 3.5 violation: Storage account '%s' does not have file encryption enabled.", [resource.name])
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    resource.properties.encryption.keySource != "Microsoft.Keyvault"
    msg := sprintf("PCI DSS 3.5/3.6 violation: Storage account '%s' does not use customer-managed keys.", [resource.name])
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    resource.properties.publicNetworkAccess != "Disabled"
    msg := sprintf("PCI DSS 3.4 violation: Storage account '%s' allows public network access.", [resource.name])
}

# PCI DSS Requirement 6: Develop and Maintain Secure Systems and Software
allow if {
    some resource in input.resources
    resource.type == "Microsoft.Security/securitySolutions"
    resource.properties.status == "Enabled"
}

allow if {
    some resource in input.resources
    resource.type == "Microsoft.Compute/virtualMachines"
    resource.properties.securityProfile.securityType == "TrustedLaunch"
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Security/securitySolutions"
    not resource.properties.status == "Enabled"
    msg := sprintf("PCI DSS 6.3 violation: Security solution for vulnerability scanning not enabled on '%s'.", [resource.name])
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Compute/virtualMachines"
    not resource.properties.securityProfile.securityType == "TrustedLaunch"
    msg := sprintf("PCI DSS 6.3.3 violation: VM '%s' does not have trusted launch for secure patching.", [resource.name])
}

# PCI DSS Requirement 7: Restrict Access by Business Need to Know
allow if {
    some resource in input.resources
    resource.type == "Microsoft.Authorization/roleAssignments"
    not (resource.properties.scope == "/" and resource.properties.roleDefinitionId == "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c")
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Authorization/roleAssignments"
    resource.properties.scope == "/"
    resource.properties.roleDefinitionId == "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c" # Contributor role
    msg := sprintf("PCI DSS 7.2 violation: Broad Contributor role assigned at subscription level to '%s'. Use least privilege.", [resource.properties.principalId])
}

# PCI DSS Requirement 8: Identify and Authenticate Access
allow if {
    some resource in input.resources
    resource.type == "Microsoft.AAD/domains"
    resource.properties.isMfaEnabled
}

allow if {
    input.azure_ad_password_policy.min_length >= 12
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.AAD/domains"
    not resource.properties.isMfaEnabled
    msg := "PCI DSS 8.3 violation: MFA not enabled for Azure AD domain."
}

deny[msg] {
    not input.azure_ad_password_policy.min_length >= 12
    msg := "PCI DSS 8.3.6 violation: Azure AD password minimum length less than 12 characters."
}

# PCI DSS Requirement 9: Restrict Physical Access
allow if {
    some resource in input.resources
    resource.type == "Microsoft.Compute/virtualMachines"
    resource.properties.securityProfile.securityType == "ConfidentialVM"
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Compute/virtualMachines"
    not resource.properties.securityProfile.securityType == "ConfidentialVM"
    msg := sprintf("PCI DSS 9 violation: VM '%s' does not use Confidential Computing for physical access restriction equivalent.", [resource.name])
}

# PCI DSS Requirement 10: Log and Monitor Access
allow if {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    resource.properties.publicNetworkAccess == "Disabled"
}

allow if {
    some resource in input.resources
    resource.type == "Microsoft.OperationalInsights/workspaces"
}

allow if {
    some resource in input.resources
    resource.type == "Microsoft.Insights/activityLogAlerts"
    resource.properties.enabled
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    not resource.properties.publicNetworkAccess == "Disabled"
    msg := sprintf("PCI DSS 10.2 violation: Storage account '%s' does not have public access disabled for logging security.", [resource.name])
}

deny[msg] {
    not any_resource_with_type("Microsoft.OperationalInsights/workspaces")
    msg := "PCI DSS 10.5 violation: No Log Analytics workspace for audit log retention."
}

deny[msg] {
    some resource in input.resources
    resource.type == "Microsoft.Insights/activityLogAlerts"
    not resource.properties.enabled
    msg := sprintf("PCI DSS 10.7 violation: Activity log alert '%s' is not enabled.", [resource.name])
}

# Helper function to check resource type existence
any_resource_with_type(resource_type) {
    some resource in input.resources
    resource.type == resource_type
}
