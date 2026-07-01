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
    severity = "low"
    if upgradable_count > 50:
        severity = "high"
    elif upgradable_count > 0:
        severity = "medium"

    return {
        "severity": severity,
        "metrics": {
            "hostname": parsed["hostname"],
            "os": parsed["os"],
            "kernel": parsed["kernel"],
            "uptime": parsed["uptime"],
            "upgradable_count": upgradable_count,
        },
        "examples": parsed["upgradable_packages"][:10],
    }


def main():
    with open("tmp/system_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_system_raw(handle.read())

    report = build_report(parsed)

    with open("tmp/system.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()
