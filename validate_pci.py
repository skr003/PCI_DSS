#!/usr/bin/env python3
"""
pci_dss_checker.py (extended)

Reads output/azure.json and produces output/pci_dss_drifts.json
in an OPA-like shape used by validate_pci.sh.

Extended checks added:
 - Storage: https-only, public blob access, encryption at rest, soft-delete/versioning, diagnostic logging
 - VMs: admin ssh key non-empty, disk encryption, diagnostic logging
 - NSGs: presence and no wide-open inbound rules for SSH(22)/RDP(3389)
 - Key Vault/Keys: rotation policy presence, soft-delete/purge protection
 - Generic: diagnostic logging missing

This script uses heuristics to find relevant fields. Tweak the key names or add explicit mapping
if your azure.json uses different field names/paths.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

OUTPUT_DIR = "output"
INPUT_FILE = os.path.join(OUTPUT_DIR, "azure.json")
DRIFT_FILE = os.path.join(OUTPUT_DIR, "pci_dss_drifts.json")


def load_input(path: str) -> Any:
    if not os.path.exists(path):
        print(f"[!] Input file not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(path, "r") as f:
        return json.load(f)


def add_violation(violations: Dict[str, bool], msg: str):
    violations[msg] = True


def get_field_any(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    """Return first found value for any key in keys (shallow search)."""
    for k in keys:
        if k in d:
            return d[k]
    return None


def truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (str,)):
        return val.strip().lower() not in ("", "false", "0", "no", "none", "null")
    if val is None:
        return False
    if isinstance(val, (list, dict)):
        return len(val) > 0
    return bool(val)


#
# Storage checks
#
def check_storage_account(sa: Dict[str, Any], violations: Dict[str, bool]):
    name = sa.get("name") or sa.get("id") or "<unknown-storage>"
    # HTTPS-only (secure transfer)
    https_only = get_field_any(sa, ["httpsOnly", "enableHttpsTrafficOnly", "enable_https_traffic_only", "properties.enableHttpsTrafficOnly"])
    if not truthy(https_only):
        add_violation(
            violations,
            f"PCI DSS Req 3 Violation: Storage account {name} does not enforce HTTPS-only traffic."
        )

    # Public blob access
    public_access = get_field_any(sa, ["allowBlobPublicAccess", "publicAccess", "properties.allowBlobPublicAccess"])
    if truthy(public_access):
        add_violation(
            violations,
            f"PCI DSS Req 3 Violation: Storage account {name} allows public blob access."
        )

    # Encryption at rest: check if encryption settings exist and are enabled
    enc = get_field_any(sa, ["encryption", "properties.encryption", "encryption.services", "properties.encryption.services"])
    if not truthy(enc):
        add_violation(
            violations,
            f"PCI DSS Req 3 Violation: Storage account {name} does not have encryption at rest configured."
        )
    else:
        # If encryption exists, try to ensure key source present (Microsoft.Storage or Microsoft.Keyvault)
        key_source = None
        if isinstance(enc, dict):
            key_source = enc.get("keySource") or enc.get("key_source")
        if not truthy(key_source):
            # still acceptable in many cases (platform-managed), but flag if explicit negative
            pass

    # Soft delete / blob versioning
    soft_delete = get_field_any(sa, ["properties.deleteRetentionPolicy", "properties.isHnsEnabled", "enableSoftDelete", "properties.enableSoftDelete"])
    # Some providers call it blobRestorePolicy / immutabilityPolicy / isVersioningEnabled; we do a heuristic
    if not truthy(soft_delete):
        add_violation(
            violations,
            f"PCI DSS Req 3 Recommendation: Storage account {name} has no soft-delete/versioning settings detected."
        )

    # Diagnostic logging
    diag = get_field_any(sa, ["diagnosticSettings", "diagnostics", "hasDiagnostics", "has_diagnostics"])
    if not truthy(diag):
        add_violation(
            violations,
            f"PCI DSS Req 10 Violation: Resource {name} missing diagnostic logging."
        )


#
# VM checks
#
def check_vm(vm: Dict[str, Any], violations: Dict[str, bool]):
    name = vm.get("name") or vm.get("id") or "<unknown-vm>"

    # Admin SSH public key presence and not empty
    public_key = None
    # Common nested places
    for path in ("admin_ssh_key", "ssh", "osProfile", "linuxConfiguration", "properties.osProfile", "properties.linuxConfiguration"):
        node = vm.get(path) if isinstance(path, str) else None
        # try to handle dotted keys
        if node is None and "." in path:
            top, rest = path.split(".", 1)
            node = vm.get(top)
            if isinstance(node, dict):
                # shallow nested
                node = node.get(rest)
        if isinstance(node, dict):
            for k in ("public_key", "publicKey", "sshKey", "ssh_public_key", "sshPublicKey"):
                if k in node:
                    public_key = node.get(k)
                    break
        if isinstance(node, str) and node.strip().startswith("ssh-"):
            public_key = node
        if public_key:
            break

    if public_key is not None:
        if isinstance(public_key, str) and public_key.strip() == "":
            add_violation(
                violations,
                f"PCI DSS Req 8 Violation: VM {name} has an empty admin SSH public key."
            )
    # else: if public key absent, we can't assume a violation; many VMs use password auth or other flows

    # Disk encryption: check osDisk/encryptionSettings or encryptionAtHost or diskEncryptionSetId
    enc_ok = False
    # Possible places
    os_disk = get_field_any(vm, ["osDisk", "properties.storageProfile.osDisk", "properties.storageProfile"])
    if isinstance(os_disk, dict):
        # common keys
        enc_settings = get_field_any(os_disk, ["encryptionSettings", "encryption", "diskEncryptionSetId", "encryptionSettingsCollection"])
        if truthy(enc_settings):
            enc_ok = True

    # encryptionAtHost or encryptionAtHost settings at VM properties
    if not enc_ok:
        if truthy(get_field_any(vm, ["encryptionAtHost", "properties.securityProfile.encryptionAtHost"])):
            enc_ok = True

    if not enc_ok:
        add_violation(
            violations,
            f"PCI DSS Req 3 Recommendation: VM {name} does not have OS disk encryption detected."
        )

    # Diagnostic logging for VM
    diag = get_field_any(vm, ["diagnosticSettings", "diagnostics", "hasDiagnostics", "has_diagnostics"])
    if not truthy(diag):
        add_violation(
            violations,
            f"PCI DSS Req 10 Violation: Resource {name} missing diagnostic logging."
        )


#
# NSG checks
#
def check_nsg(nsg: Dict[str, Any], violations: Dict[str, bool]):
    name = nsg.get("name") or nsg.get("id") or "<unknown-nsg>"
    # Expect securityRules or properties.securityRules
    rules = get_field_any(nsg, ["securityRules", "properties.securityRules", "properties.securityRules[*]", "properties.defaultSecurityRules"])
    if not rules:
        add_violation(
            violations,
            f"PCI DSS Req 4 Recommendation: Network Security Group {name} has no security rules data to evaluate."
        )
        return
    # rules may be list
    if isinstance(rules, dict):
        # maybe keyed by name
        rules = list(rules.values())
    if not isinstance(rules, list):
        return

    for r in rules:
        # Each rule may have direction, sourceAddressPrefix(es), access, destinationPortRange/port ranges
        direction = r.get("direction", "").lower()
        access = r.get("access", "").lower()
        # source prefixes can be many forms
        src = r.get("sourceAddressPrefix") or r.get("sourceAddressPrefixes") or r.get("sourceAddressPrefixes", [])
        if isinstance(src, str):
            src_list = [src]
        elif isinstance(src, list):
            src_list = src
        else:
            src_list = []

        # port fields
        ports = r.get("destinationPortRange") or r.get("destinationPortRanges") or r.get("destinationPortRange", "")
        # normalize
        if isinstance(ports, str):
            port_text = ports
        elif isinstance(ports, list) and len(ports) > 0:
            port_text = ",".join([str(p) for p in ports])
        else:
            port_text = ""

        # check for 0.0.0.0/0 or '*' in source and inbound SSH/RDP open (allow)
        if direction == "inbound" or direction == "in":
            # normalize src_list
            for s in src_list:
                s_norm = (s or "").strip()
                if s_norm in ("0.0.0.0/0", "*", "any", "Internet", "internet"):
                    # check ports include 22 or 3389 or wildcard
                    if access == "allow":
                        if port_text == "" or port_text == "*" or "22" in port_text or "3389" in port_text:
                            add_violation(
                                violations,
                                f"PCI DSS Req 1 Violation: NSG {name} has a wide-open inbound rule allowing {s_norm} to ports {port_text or 'any'} (SSH/RDP exposure)."
                            )


#
# KeyVault checks
#
def check_keyvault(kv: Dict[str, Any], violations: Dict[str, bool]):
    name = kv.get("name") or kv.get("id") or "<unknown-kv>"
    # rotation policy for keys
    rot = get_field_any(kv, ["rotation_policy", "rotationPolicy", "properties.rotationPolicy", "properties.rotation_policy"])
    if not truthy(rot):
        add_violation(
            violations,
            f"PCI DSS Req 7 Recommendation: Key Vault {name} has no key rotation policy detected."
        )
    # soft-delete / purge protection flags
    enable_soft = get_field_any(kv, ["properties.enableSoftDelete", "enableSoftDelete", "properties.enableSoft_delete", "soft_delete"])
    if not truthy(enable_soft):
        add_violation(
            violations,
            f"PCI DSS Req 7 Recommendation: Key Vault {name} does not have soft-delete/purge protection enabled."
        )


#
# Generic resource diagnostic check
#
def check_generic_diag(r: Dict[str, Any], violations: Dict[str, bool]):
    name = r.get("name") or r.get("id") or "<unknown-resource>"
    diag = get_field_any(r, ["diagnosticSettings", "diagnostics", "hasDiagnostics", "has_diagnostics"])
    if not truthy(diag):
        add_violation(
            violations,
            f"PCI DSS Req 10 Violation: Resource {name} missing diagnostic logging."
        )


#
# Main walker / heuristics
#
def resource_is_storage(r: Dict[str, Any]) -> bool:
    typ = (r.get("type") or "").lower()
    if "storage" in typ or "storageaccounts" in typ or "microsoft.storage" in typ:
        return True
    # also if has httpsOnly or allowBlobPublicAccess
    if any(k in r for k in ("httpsOnly", "enableHttpsTrafficOnly", "allowBlobPublicAccess", "publicAccess")):
        return True
    return False


def resource_is_vm(r: Dict[str, Any]) -> bool:
    typ = (r.get("type") or "").lower()
    if "virtualmachines" in typ or "compute" in typ or "vm" in typ:
        return True
    # fallback heuristics
    if "osProfile" in r or "os_disk" in r or "osDisk" in r:
        return True
    if isinstance(r.get("name", ""), str) and "vm" in r.get("name", "").lower():
        return True
    return False


def resource_is_nsg(r: Dict[str, Any]) -> bool:
    typ = (r.get("type") or "").lower()
    return "networksecuritygroup" in typ or "network security group" in typ or "nsg" in r.get("name", "").lower()


def resource_is_kv(r: Dict[str, Any]) -> bool:
    typ = (r.get("type") or "").lower()
    return "keyvault" in typ or "vaults" in typ or "keyvault" in r.get("name", "").lower()


def main():
    data = load_input(INPUT_FILE)

    # Collect resource objects into a flat list using a few possible shapes
    resources: List[Dict[str, Any]] = []
    if isinstance(data, dict) and "resource_changes" in data:
        rc = data["resource_changes"]
        if isinstance(rc, list):
            resources = rc
    elif isinstance(data, list):
        resources = data
    elif isinstance(data, dict):
        # If top-level lists under keys, combine them
        for v in data.values():
            if isinstance(v, list):
                resources.extend(v)

    # fallback: if resources empty try scanning top-level dict values that look like resources
    if not resources and isinstance(data, dict):
        # sometimes azure.json is a mapping of id->resource
        for k, v in data.items():
            if isinstance(v, dict) and ("name" in v or "type" in v):
                resources.append(v)

    violations: Dict[str, bool] = {}

    # iterate resources and run appropriate checks
    for r in resources:
        if not isinstance(r, dict):
            continue
        # Storage
        if resource_is_storage(r):
            check_storage_account(r, violations)
            continue
        # VM
        if resource_is_vm(r):
            check_vm(r, violations)
            continue
        # NSG
        if resource_is_nsg(r):
            check_nsg(r, violations)
            continue
        # Key Vault
        if resource_is_kv(r):
            check_keyvault(r, violations)
            continue
        # Generic resource: check diagnostic logging
        check_generic_diag(r, violations)

    # Build OPA-like output shape
    opa_like = {
        "result": [
            {
                "expressions": [
                    {
                        "value": violations
                    }
                ]
            }
        ]
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(DRIFT_FILE, "w") as f:
        json.dump(opa_like, f, indent=2)

    # Print summary
    if len(violations) == 0:
        print("[✓] No PCI DSS drifts detected.")
    else:
        print(f"[✗] PCI DSS drifts found! Stored in {DRIFT_FILE}")
        for msg in violations.keys():
            print(" -", msg)


if __name__ == "__main__":
    main()
