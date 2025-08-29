import json
import os

OUTPUT_DIR = "output"
INPUT_FILE = os.path.join(OUTPUT_DIR, "azure.json")
DRIFT_FILE = os.path.join(OUTPUT_DIR, "drift.json")
RESULT_FILE = os.path.join(OUTPUT_DIR, "result.json")


def load_input(path):
    with open(path, "r") as f:
        return json.load(f)


def check_pci_dss(data):
    deny = []
    passed = []

    # ------------------------------
    # 10.1 – VM diagnostic logging
    # ------------------------------
    for vm in data.get("vms", []):
        if vm.get("diagnostics_enabled"):
            passed.append(
                f"PCI DSS Req 10.1 Passed: VM {vm['name']} has diagnostic logging enabled."
            )
        else:
            deny.append(
                f"PCI DSS Req 10.1 Violation: VM {vm['name']} missing diagnostic logging."
            )

    # ------------------------------
    # 10.2 – Audit logs implemented
    # ------------------------------
    for ds in data.get("diagnostics", []):
        logs = ds.get("logs", [])
        has_enabled = any(log.get("enabled", False) for log in logs)
        if has_enabled:
            passed.append(
                f"PCI DSS Req 10.2 Passed: Diagnostic setting {ds['name']} has audit logs enabled."
            )
        else:
            deny.append(
                f"PCI DSS Req 10.2 Violation: Diagnostic setting {ds['name']} has no audit logs enabled."
            )

    # ------------------------------
    # 10.5 – Log retention (>= 365 days)
    # ------------------------------
    for ws in data.get("workspaces", []):
        retention = ws.get("retentionInDays", 0)
        if retention >= 365:
            passed.append(
                f"PCI DSS Req 10.5 Passed: Log Analytics workspace {ws['name']} retains logs for {retention} days."
            )
        else:
            deny.append(
                f"PCI DSS Req 10.5 Violation: Log Analytics workspace {ws['name']} retains logs for only {retention} days."
            )

    # ------------------------------
    # 10.7 – Alerts enabled
    # ------------------------------
    for alert in data.get("alerts", []):
        if alert.get("enabled", False):
            passed.append(
                f"PCI DSS Req 10.7 Passed: Metric alert {alert['name']} is enabled."
            )
        else:
            deny.append(
                f"PCI DSS Req 10.7 Violation: Metric alert {alert['name']} is disabled."
            )

    return deny, passed


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: {INPUT_FILE} not found. Run collect_azure_data.sh first.")
        return

    data = load_input(INPUT_FILE)
    deny, passed = check_pci_dss(data)

    # Write drift.json (violations only)
    with open(DRIFT_FILE, "w") as f:
        json.dump(deny, f, indent=2)

    # Write result.json (object with pass & deny)
    with open(RESULT_FILE, "w") as f:
        json.dump({"deny": deny, "pass": passed}, f, indent=2)

    print("[*] Validation complete")
    print(f"    - Violations → {DRIFT_FILE} ({len(deny)})")
    print(f"    - Full report → {RESULT_FILE} (Pass: {len(passed)} / Fail: {len(deny)})")


if __name__ == "__main__":
    main()
