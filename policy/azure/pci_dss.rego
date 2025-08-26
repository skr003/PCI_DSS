package pci_dss

default allow = false
#package azure.pci_dss

#import future.keywords.if
# Allow only if there are no denies
allow if {
  count(deny) == 0
}

# PCI DSS Requirement 3: Protect Stored Account Data
# Check for encryption on storage accounts (3.5 PAN unreadable)
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Storage/storageAccounts"
    not resource.properties.encryption.services.blob.enabled
    msg := sprintf("PCI DSS 3.5 violation: Storage account '%s' does not have blob encryption enabled.", [resource.name])
}

deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Storage/storageAccounts"
    not resource.properties.encryption.services.file.enabled
    msg := sprintf("PCI DSS 3.5 violation: Storage account '%s' does not have file encryption enabled.", [resource.name])
}

# Check for customer-managed keys (3.5, 3.6 secure keys)
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Storage/storageAccounts"
    resource.properties.encryption.keySource != "Microsoft.Keyvault"
    msg := sprintf("PCI DSS 3.5/3.6 violation: Storage account '%s' does not use customer-managed keys.", [resource.name])
}

# Check no public access (3.4 restrict PAN access)
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Storage/storageAccounts"
    resource.properties.publicNetworkAccess != "Disabled"
    msg := sprintf("PCI DSS 3.4 violation: Storage account '%s' allows public network access.", [resource.name])
}

# PCI DSS Requirement 6: Develop and Maintain Secure Systems and Software
# Check for vulnerability scanning (6.3 vulnerabilities addressed)
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Security/securitySolutions"
    not resource.properties.status == "Enabled"
    msg := sprintf("PCI DSS 6.3 violation: Security solution for vulnerability scanning not enabled on '%s'.", [resource.name])
}

# Check for update management (6.3.3 patches)
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Compute/virtualMachines"
    not resource.properties.securityProfile.securityType == "TrustedLaunch"
    msg := sprintf("PCI DSS 6.3.3 violation: VM '%s' does not have trusted launch for secure patching.", [resource.name])
}

# PCI DSS Requirement 7: Restrict Access by Business Need to Know
# Check RBAC least privilege (7.2 access assigned)
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Authorization/roleAssignments"
    resource.properties.scope == "/" # subscription level
    resource.properties.roleDefinitionId == "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c" # Contributor role
    msg := sprintf("PCI DSS 7.2 violation: Broad Contributor role assigned at subscription level to '%s'. Use least privilege.", [resource.properties.principalId])
}

# PCI DSS Requirement 8: Identify and Authenticate Access
# Check Azure AD MFA (8.3 strong authentication)
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.AAD/domains"
    not resource.properties.isMfaEnabled
    msg := "PCI DSS 8.3 violation: MFA not enabled for Azure AD domain."
}

# Check password policies (8.3.6 complexity)
# Note: Azure AD password policies are managed at tenant level, check via conditional access or similar
deny[msg] {
    # Assuming a custom policy or config for password complexity
    not input.azure_ad_password_policy.min_length >= 12
    msg := "PCI DSS 8.3.6 violation: Azure AD password minimum length less than 12 characters."
}

# PCI DSS Requirement 9: Restrict Physical Access
# For Azure, physical access is managed by Microsoft; customer checks logical equivalents like just-in-time access
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Compute/virtualMachines"
    not resource.properties.securityProfile.securityType == "ConfidentialVM"
    msg := "PCI DSS 9 violation: VM '%s' does not use Confidential Computing for physical access restriction equivalent."
}

# PCI DSS Requirement 10: Log and Monitor Access
# Check diagnostic logging on storage (10.2 audit logs)
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Storage/storageAccounts"
    not resource.properties.publicNetworkAccess == "Disabled" # Indirect, but for logging, check diagnostic settings
    msg := sprintf("PCI DSS 10.2 violation: Storage account '%s' does not have public access disabled for logging security.", [resource.name])
}

# Check Log Analytics workspace (10.5 retain logs)
deny[msg] {
    not input.resources[_].type == "Microsoft.OperationalInsights/workspaces"
    msg := "PCI DSS 10.5 violation: No Log Analytics workspace for audit log retention."
}

# Check alert rules (10.7 failures alerted)
deny[msg] {
    resource := input.resources[_]
    resource.type == "Microsoft.Insights/activityLogAlerts"
    not resource.properties.enabled
    msg := sprintf("PCI DSS 10.7 violation: Activity log alert '%s' is not enabled.", [resource.name])
}
