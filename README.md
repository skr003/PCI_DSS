# PCI DSS Compliance Pipeline

This repository provides a demo Jenkins pipeline and Terraform IaC code to deploy
Azure resources (Storage, VM, SQL DB, IAM role assignment) with PCI DSS and CIS compliance checks.

## Components

- **Terraform**: Deploy Azure infra
- **Jenkins**: CI/CD pipeline
- **OPA/Rego (Conftest)**: Policy-as-code enforcement
- **Checkov**: Static analysis for IaC compliance
- **Azure Policy**: Runtime compliance checks (optional)

## Usage

1. Clone repo
2. Update `terraform/main.tf` with your SSH keys, passwords, and AAD principal IDs
3. Run Jenkins pipeline

Artifacts:
- `tfplan.json` (Terraform plan)
- Compliance violations (OPA/Checkov)
- Azure Policy summaries

