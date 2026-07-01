#!/usr/bin/env python3
import json


def parse_system_raw(raw_text):
    lines = [line.rstrip("\n") for line in raw_text.splitlines()]
    data = {
        "hostname": "unknown",
        "os": "unknown",
        "kernel": "unknown",
        "uptime": "unknown",
        "upgradable_packages": [],
    }

    in_upgradable = False
    for line in lines:
        if line == "__UPGRADABLE_START__":
            in_upgradable = True
            continue
        if line == "__UPGRADABLE_END__":
            in_upgradable = False
            continue

        if in_upgradable:
            if line.strip():
                data["upgradable_packages"].append(line.strip())
            continue

        if "=" in line:
            key, value = line.split("=", 1)
            normalized = key.strip().upper()
            if normalized == "HOSTNAME":
                data["hostname"] = value.strip()
            elif normalized == "OS":
                data["os"] = value.strip()
            elif normalized == "KERNEL":
                data["kernel"] = value.strip()
            elif normalized == "UPTIME":
                data["uptime"] = value.strip()

    return data


def build_report(parsed):
    upgradable_count = len(parsed["upgradable_packages"])

    if upgradable_count > 50:
        severity = "high"
        risk_score = min(100, 67 + (upgradable_count - 50))
        severity_reason = (
            f"{upgradable_count} pending upgrades exceed the high threshold (>50). "
            "A severely outdated system exposes known CVEs across multiple packages."
        )
    elif upgradable_count > 0:
        severity = "medium"
        risk_score = min(66, 1 + upgradable_count)
        severity_reason = (
            f"{upgradable_count} pending package upgrade(s) detected. "
            "Unpatched packages may contain exploitable vulnerabilities."
        )
    else:
        severity = "low"
        risk_score = 0
        severity_reason = "No pending package upgrades detected. System packages are up to date."

    triggered_rules = []
    if upgradable_count > 50:
        triggered_rules.append(f"upgradable_count > 50 (actual: {upgradable_count})")
    elif upgradable_count > 0:
        triggered_rules.append(f"upgradable_count > 0 (actual: {upgradable_count})")

    return {
        "severity": severity,
        "risk_score": risk_score,
        "severity_reason": severity_reason,
        "triggered_rules": triggered_rules,
        "thresholds": {
            "high":   "upgradable_count > 50  -> risk_score 67-100",
            "medium": "upgradable_count > 0   -> risk_score 1-66",
            "low":    "upgradable_count == 0  -> risk_score 0",
        },
        "metrics": {
            "hostname": parsed["hostname"],
            "os": parsed["os"],
            "kernel": parsed["kernel"],
            "uptime": parsed["uptime"],
            "upgradable_count": upgradable_count,
        },
        "examples": parsed["upgradable_packages"][:10],
        "remediation": [
            {
                "description": "Apply all pending security updates",
                "command": "sudo apt update && sudo apt upgrade -y",
                "impact": "Patches known CVEs across installed packages.",
            },
            {
                "description": "List packages pending upgrade",
                "command": "apt list --upgradable 2>/dev/null",
                "impact": "Helps prioritise critical security patches before applying.",
            },
            {
                "description": "Enable automatic security updates",
                "command": "sudo apt install unattended-upgrades -y && sudo dpkg-reconfigure unattended-upgrades",
                "impact": "Automates delivery of security patches between manual audits.",
            },
        ],
    }


def main():
    with open("tmp/system_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_system_raw(handle.read())

    report = build_report(parsed)

    with open("tmp/system.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()