package pci_dss

# PCI DSS 3.4: Storage must enforce HTTPS
deny[msg] {
  some s
  input.resource_changes[s].httpsOnly == false
  msg := sprintf("PCI DSS 3.4 Violation: Storage account %s does not enforce HTTPS", [input.resource_changes[s].name])
}

# PCI DSS 1.2: Storage must block public blob access
deny[msg] {
  some s
  input.resource_changes[s].publicAccess == true
  msg := sprintf("PCI DSS 1.2 Violation: Storage account %s allows public access", [input.resource_changes[s].name])
}

# PCI DSS 2.2.1: VMs must specify OS
deny[msg] {
  some v
  not input.resource_changes[v].os
  msg := sprintf("PCI DSS 2.2.1 Violation: VM %s does not specify OS type", [input.resource_changes[v].name])
}
