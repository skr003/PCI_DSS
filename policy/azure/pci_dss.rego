package azure.pci_dss

import future.keywords.if

# Default deny state
default deny = false

# PCI DSS Requirement 3: Protect Stored Account Data
if {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    not resource.properties.encryption.services.blob.enabled
} {
    deny := true
    msg := sprintf("PCI DSS 3.5 violation: Storage account '%s' does not have blob encryption enabled.", [resource.name])
}

if {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    not resource.properties.encryption.services.file.enabled
} {
    deny := true
    msg := sprintf("PCI DSS 3.5 violation: Storage account '%s' does not have file encryption enabled.", [resource.name])
}

if {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    resource.properties.encryption.keySource != "Microsoft.Keyvault"
} {
    deny := true
    msg := sprintf("PCI DSS 3.5/3.6 violation: Storage account '%s' does not use customer-managed keys.", [resource.name])
}

if {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    resource.properties.publicNetworkAccess != "Disabled"
} {
    deny := true
    msg := sprintf("PCI DSS 3.4 violation: Storage account '%s' allows public network access.", [resource.name])
}

# PCI DSS Requirement 6: Develop and Maintain Secure Systems and Software
if {
    some resource in input.resources
    resource.type == "Microsoft.Security/securitySolutions"
    not resource.properties.status == "Enabled"
} {
    deny := true
    msg := sprintf("PCI DSS 6.3 violation: Security solution for vulnerability scanning not enabled on '%s'.", [resource.name])
}

if {
    some resource in input.resources
    resource.type == "Microsoft.Compute/virtualMachines"
    not resource.properties.securityProfile.securityType == "TrustedLaunch"
} {
    deny := true
    msg := sprintf("PCI DSS 6.3.3 violation: VM '%s' does not have trusted launch for secure patching.", [resource.name])
}

# PCI DSS Requirement 7: Restrict Access by Business Need to Know
if {
    some resource in input.resources
    resource.type == "Microsoft.Authorization/roleAssignments"
    resource.properties.scope == "/"
    resource.properties.roleDefinitionId == "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c" # Contributor role
} {
    deny := true
    msg := sprintf("PCI DSS 7.2 violation: Broad Contributor role assigned at subscription level to '%s'. Use least privilege.", [resource.properties.principalId])
}

# PCI DSS Requirement 8: Identify and Authenticate Access
if {
    some resource in input.resources
    resource.type == "Microsoft.AAD/domains"
    not resource.properties.isMfaEnabled
} {
    deny := true
    msg := "PCI DSS 8.3 violation: MFA not enabled for Azure AD domain."
}

if {
    not input.azure_ad_password_policy.min_length >= 12
} {
    deny := true
    msg := "PCI DSS 8.3.6 violation: Azure AD password minimum length less than 12 characters."
}

# PCI DSS Requirement 9: Restrict Physical Access
if {
    some resource in input.resources
    resource.type == "Microsoft.Compute/virtualMachines"
    not resource.properties.securityProfile.securityType == "ConfidentialVM"
} {
    deny := true
    msg := sprintf("PCI DSS 9 violation: VM '%s' does not use Confidential Computing for physical access restriction equivalent.", [resource.name])
}

# PCI DSS Requirement 10: Log and Monitor Access
if {
    some resource in input.resources
    resource.type == "Microsoft.Storage/storageAccounts"
    not resource.properties.publicNetworkAccess == "Disabled" # Indirect check for logging security
} {
    deny := true
    msg := sprintf("PCI DSS 10.2 violation: Storage account '%s' does not have public access disabled for logging security.", [resource.name])
}

if {
    not any_resource_with_type("Microsoft.OperationalInsights/workspaces")
} {
    deny := true
    msg := "PCI DSS 10.5 violation: No Log Analytics workspace for audit log retention."
}

if {
    some resource in input.resources
    resource.type == "Microsoft.Insights/activityLogAlerts"
    not resource.properties.enabled
} {
    deny := true
    msg := sprintf("PCI DSS 10.7 violation: Activity log alert '%s' is not enabled.", [resource.name])
}

# Helper function to check resource type existence
any_resource_with_type(resource_type) {
    some resource in input.resources
    resource.type == resource_type
}
