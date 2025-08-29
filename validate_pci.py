#!/usr/bin/env python3
"""
pci_dss_checker_plain.py

Reads output/azure.json and prints ONLY violation messages (one per line).
No JSON, no extra context.
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
        return val.strip().lower() not in ("", "false", "0", "no", "none", "null")
    if val is None:
        return False
    if isinstance(val, (list, dict)):
        return len(val) > 0
    return bool(val)


def add_violation(violations: List[str], msg: str):
    violations.append(msg)


def check_storage_account(sa: Dict[str, Any], violations: List[str]):
    name = sa.get("name") or sa.get("id") or "<unknown-storage>"
    https_only = get_field_any(sa, ["httpsOnly", "enableHttpsTrafficOnly"])
    if not truthy(https_only):
        add_violation(violations, f"PCI DSS Req 3 Violation: Storage account {name} does not enforce HTTPS-only traffic.")

    public_access = get_field_any(sa, ["allowBlobPublicAccess", "publicAccess"])
    if truthy(public_access):
        add_violation(violations, f"PCI DSS Req 3 Violation: Storage account {name} allows public blob access.")

    diag = get_field_any(sa, ["diagnosticSettings", "diagnostics", "hasDiagnostics"])
    if not truthy(diag):
        add_violation(violations, f"PCI DSS Req 10 Violation: Resource {name} missing diagnostic logging.")


def check_vm(vm: Dict[str, Any], violations: List[str]):
    name = vm.get("name") or vm.get("id") or "<unknown-vm>"
    diag = get_field_any(vm, ["diagnosticSettings", "diagnostics", "hasDiagnostics"])
    if not truthy(diag):
        add_violation(violations, f"PCI DSS Req 10 Violation: Resource {name} missing diagnostic logging.")


def main():
    data = load_input(INPUT_FILE)

    resources: List[Dict[str, Any]] = []
    if isinstance(data, dict) and "resource_changes" in data:
        rc = data["resource_changes"]
        if isinstance(rc, list):
            resources = rc
    elif isinstance(data, list):
        resources = data

    violations: List[str] = []

    for r in resources:
        if not isinstance(r, dict):
            continue
        if "httpsOnly" in r or "enableHttpsTrafficOnly" in r:
            check_storage_account(r, violations)
        elif "osProfile" in r or "vm" in (r.get("name", "").lower()):
            check_vm(r, violations)
        else:
            name = r.get("name") or "<unknown>"
            diag = get_field_any(r, ["diagnosticSettings", "diagnostics", "hasDiagnostics"])
            if not truthy(diag):
                add_violation(violations, f"PCI DSS Req 10 Violation: Resource {name} missing diagnostic logging.")

    for v in violations:
        print(v)


if __name__ == "__main__":
    main()
