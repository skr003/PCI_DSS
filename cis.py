#!/usr/bin/env python3
"""
cis_storage_checker_plain.py

Reads output/azure.json and prints ONLY CIS Storage-related violation messages.

Implements CIS Microsoft Azure Foundations Benchmark v4.0.0
Section 10: Storage Services
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

INPUT_FILE = "output/azure.json"


def load_input(path: str) -> Any:
    if not os.path.exists(path):
        print(f"[!] Input file not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(path, "r") as f:
        return json.load(f)


def get_field_any(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    for k in keys:
        if k in d:
            return d[k]
    return None


def truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "yes", "enabled", "1")
    return bool(val)


def add_violation(violations: List[str], msg: str):
    violations.append(msg)


# 10.1 Azure Files
def check_azure_files(sa: Dict[str, Any], violations: List[str]):
    name = sa.get("name") or "<unknown-storage>"

    soft_delete = get_field_any(sa, ["fileSoftDelete", "properties.fileServices.deleteRetentionPolicy.enabled"])
    if not truthy(soft_delete):
        add_violation(violations, f"CIS 10.1.1 Violation: Azure File Share {name} does not have soft delete enabled.")

    smb_version = get_field_any(sa, ["smbProtocolVersion", "properties.minimumTlsVersion"])
    if smb_version and str(smb_version) < "3.1.1":
        add_violation(violations, f"CIS 10.1.2 Violation: Azure File Share {name} SMB protocol version is below 3.1.1.")

    smb_encryption = get_field_any(sa, ["smbChannelEncryption"])
    if smb_encryption and "AES-256-GCM" not in str(smb_encryption):
        add_violation(violations, f"CIS 10.1.3 Violation: Azure File Share {name} SMB channel encryption is not AES-256-GCM or higher.")


# 10.2 Azure Blob Storage
def check_blob(sa: Dict[str, Any], violations: List[str]):
    name = sa.get("name") or "<unknown-storage>"

    soft_delete = get_field_any(sa, ["blobSoftDelete", "properties.deleteRetentionPolicy.enabled"])
    if not truthy(soft_delete):
        add_violation(violations, f"CIS 10.2.1 Violation: Blob storage {name} does not have soft delete enabled.")

    versioning = get_field_any(sa, ["isVersioningEnabled", "properties.isVersioningEnabled"])
    if not truthy(versioning):
        add_violation(violations, f"CIS 10.2.2 Violation: Blob storage {name} does not have versioning enabled.")


# 10.3 Storage Accounts (general)
def check_storage_account(sa: Dict[str, Any], violations: List[str]):
    name = sa.get("name") or "<unknown-storage>"

    # 10.3.1.1 Key rotation reminders
    key_rotation = get_field_any(sa, ["keyRotationReminders", "properties.keyCreationTime"])
    if not truthy(key_rotation):
        add_violation(violations, f"CIS 10.3.1.1 Violation: Storage account {name} does not have key rotation reminders enabled.")

    # 10.3.1.2 Keys periodically regenerated (simplified: check last key creation date)
    key_age = get_field_any(sa, ["keyCreationTime"])
    if key_age is None:
        add_violation(violations, f"CIS 10.3.1.2 Violation: Storage account {name} has no record of key regeneration.")

    # 10.3.1.3 Disable key access
    allow_key_access = get_field_any(sa, ["allowSharedKeyAccess", "properties.allowSharedKeyAccess"])
    if truthy(allow_key_access):
        add_violation(violations, f"CIS 10.3.1.3 Violation: Storage account {name} allows shared key access.")

    # 10.3.2.1 Private endpoints
    pe = get_field_any(sa, ["privateEndpoints", "properties.privateEndpointConnections"])
    if not truthy(pe):
        add_violation(violations, f"CIS 10.3.2.1 Violation: Storage account {name} does not use private endpoints.")

    # 10.3.2.2 Public network access disabled
    pna = get_field_any(sa, ["publicNetworkAccess", "properties.publicNetworkAccess"])
    if str(pna).lower() != "disabled":
        add_violation(violations, f"CIS 10.3.2.2 Violation: Storage account {name} allows public network access.")

    # 10.3.2.3 Default deny
    default_rule = get_field_any(sa, ["defaultAction", "properties.networkAcls.defaultAction"])
    if str(default_rule).lower() != "deny":
        add_violation(violations, f"CIS 10.3.2.3 Violation: Storage account {name} does not default deny network access.")

    # 10.3.3.1 Entra authorization
    entra_auth = get_field_any(sa, ["defaultToAzureADAuth", "properties.azureADAuth"])
    if not truthy(entra_auth):
        add_violation(violations, f"CIS 10.3.3.1 Violation: Storage account {name} is not defaulting to Microsoft Entra authorization.")

    # 10.3.4 Secure transfer required
    https_only = get_field_any(sa, ["enableHttpsTrafficOnly"])
    if not truthy(https_only):
        add_violation(violations, f"CIS 10.3.4 Violation: Storage account {name} does not enforce secure transfer.")

    # 10.3.5 Trusted services
    trusted = get_field_any(sa, ["bypass", "properties.networkAcls.bypass"])
    if trusted and "AzureServices" not in str(trusted):
        add_violation(violations, f"CIS 10.3.5 Violation: Storage account {name} does not allow trusted Azure services.")

    # 10.3.6 Soft delete for containers/blobs
    container_delete = get_field_any(sa, ["containerDeleteRetentionPolicy", "properties.containerDeleteRetentionPolicy"])
    if not truthy(container_delete):
        add_violation(violations, f"CIS 10.3.6 Violation: Storage account {name} does not have soft delete enabled for containers/blobs.")

    # 10.3.7 TLS version
    tls = get_field_any(sa, ["minimumTlsVersion", "properties.minimumTlsVersion"])
    if str(tls) not in ("TLS1_2", "1.2", "TLS1.2"):
        add_violation(violations, f"CIS 10.3.7 Violation: Storage account {name} TLS version is not 1.2.")

    # 10.3.8 Cross-tenant replication
    xtr = get_field_any(sa, ["allowCrossTenantReplication"])
    if truthy(xtr):
        add_violation(violations, f"CIS 10.3.8 Violation: Storage account {name} allows cross-tenant replication.")

    # 10.3.9 Anonymous blob access
    anon = get_field_any(sa, ["allowBlobPublicAccess"])
    if truthy(anon):
        add_violation(violations, f"CIS 10.3.9 Violation: Storage account {name} allows anonymous blob access.")

    # 10.3.10 Delete lock
    locks = get_field_any(sa, ["resourceLocks"])
    if not locks or "Delete" not in str(locks):
        add_violation(violations, f"CIS 10.3.10 Violation: Storage account {name} has no delete lock.")

    # 10.3.11 ReadOnly lock
    if not locks or "ReadOnly" not in str(locks):
        add_violation(violations, f"CIS 10.3.11 Violation: Storage account {name} has no read-only lock.")

    # 10.3.12 Redundancy GRS
    redundancy = get_field_any(sa, ["sku", "sku.name"])
    if redundancy and "GRS" not in str(redundancy):
        add_violation(violations, f"CIS 10.3.12 Violation: Storage account {name} is not geo-redundant (GRS).")


# Heuristic: detect storage accounts in azure.json
def resource_is_storage(r: Dict[str, Any]) -> bool:
    t = (r.get("type") or "").lower()
    return "storage" in t or "storageaccounts" in t or "microsoft.storage" in t


def main():
    data = load_input(INPUT_FILE)

    resources = []
    if isinstance(data, dict) and "resource_changes" in data:
        resources = data["resource_changes"]
    elif isinstance(data, list):
        resources = data

    violations: List[str] = []

    for r in resources:
        if not isinstance(r, dict):
            continue
        if resource_is_storage(r):
            check_azure_files(r, violations)
            check_blob(r, violations)
            check_storage_account(r, violations)

    for v in violations:
        print(v)


if __name__ == "__main__":
    main()
