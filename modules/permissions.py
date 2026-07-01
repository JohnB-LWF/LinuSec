#!/usr/bin/env python3
import json


def parse_sections(raw_text):
    sections = {}
    current = None
    for line in raw_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("__") and stripped.endswith("_START__"):
            current = stripped[len("__"):-len("_START__")]
            sections[current] = []
            continue
        if stripped.startswith("__") and stripped.endswith("_END__"):
            current = None
            continue
        if current is not None and line.strip():
            sections[current].append(line.strip())
    return sections


def parse_permissions_raw(raw_text):
    sections = parse_sections(raw_text)
    suid = sections.get("SUID", [])
    sgid = sections.get("SGID", [])
    world_writable_dirs = sections.get("WORLD_WRITABLE_DIRS", [])
    home_perms = sections.get("HOME_PERMS", [])

    insecure_homes = []
    for entry in home_perms:
        parts = entry.split(maxsplit=1)
        if len(parts) != 2:
            continue
        mode_text, path = parts
        if not mode_text.isdigit():
            continue
        mode = int(mode_text)
        if mode > 750:
            insecure_homes.append(f"{mode_text} {path}")

    return {
        "suid": suid,
        "sgid": sgid,
        "world_writable_dirs": world_writable_dirs,
        "insecure_homes": insecure_homes,
    }


def build_report(parsed):
    suid_count = len(parsed["suid"])
    sgid_count = len(parsed["sgid"])
    world_writable_count = len(parsed["world_writable_dirs"])
    insecure_home_count = len(parsed["insecure_homes"])

    if world_writable_count > 20 or insecure_home_count > 0:
        severity = "high"
        risk_score = min(100, 67 + insecure_home_count * 5 + max(0, world_writable_count - 20))
    elif world_writable_count > 0 or (suid_count + sgid_count) > 20:
        severity = "medium"
        risk_score = min(66, 1 + world_writable_count * 5 + max(0, suid_count + sgid_count - 20))
    else:
        severity = "low"
        risk_score = 0

    triggered_rules = []
    if insecure_home_count > 0:
        triggered_rules.append(f"insecure_home_dir_count > 0 (actual: {insecure_home_count})")
    if world_writable_count > 20:
        triggered_rules.append(f"world_writable_dir_count > 20 (actual: {world_writable_count})")
    elif world_writable_count > 0:
        triggered_rules.append(f"world_writable_dir_count > 0 (actual: {world_writable_count})")
    if (suid_count + sgid_count) > 20:
        triggered_rules.append(f"suid_count + sgid_count > 20 (actual: {suid_count + sgid_count})")

    reasons = []
    if insecure_home_count > 0:
        reasons.append(f"{insecure_home_count} home dir(s) with permissions > 750")
    if world_writable_count > 0:
        reasons.append(f"{world_writable_count} world-writable dir(s) found")
    if (suid_count + sgid_count) > 20:
        reasons.append(f"{suid_count + sgid_count} SUID/SGID binaries (elevated count)")

    if reasons:
        severity_reason = severity.upper() + ": " + "; ".join(reasons) + "."
    else:
        severity_reason = "No critical permission issues detected."

    return {
        "severity": severity,
        "risk_score": risk_score,
        "severity_reason": severity_reason,
        "triggered_rules": triggered_rules,
        "thresholds": {
            "high":   "world_writable_dirs > 20 OR insecure_homes > 0  -> risk_score 67-100",
            "medium": "world_writable_dirs > 0 OR suid+sgid > 20       -> risk_score 1-66",
            "low":    "none of the above                                -> risk_score 0",
        },
        "metrics": {
            "suid_count": suid_count,
            "sgid_count": sgid_count,
            "world_writable_dir_count": world_writable_count,
            "insecure_home_dir_count": insecure_home_count,
        },
        "examples": {
            "suid": parsed["suid"][:10],
            "sgid": parsed["sgid"][:10],
            "world_writable_dirs": parsed["world_writable_dirs"][:10],
            "insecure_homes": parsed["insecure_homes"][:10],
        },
        "remediation": [
            {
                "description": "Fix insecure home directory permissions",
                "command": "chmod 700 /home/<username>",
                "impact": "Prevents other users from reading home directory contents.",
            },
            {
                "description": "Find all world-writable directories",
                "command": "find / -xdev -type d -perm -0002 2>/dev/null | grep -v /proc",
                "impact": "World-writable dirs can be used for privilege escalation.",
            },
            {
                "description": "Remove world-writable bit from a directory",
                "command": "chmod o-w /path/to/dir",
                "impact": "Restricts unauthorised write access.",
            },
            {
                "description": "Audit all SUID binaries",
                "command": "find / -xdev -type f -perm -4000 2>/dev/null",
                "impact": "SUID binaries run as their owner; excess ones increase attack surface.",
            },
            {
                "description": "Remove unnecessary SUID bit",
                "command": "sudo chmod u-s /path/to/binary",
                "impact": "Reduces privilege escalation opportunities.",
            },
        ],
    }


def main():
    with open("tmp/permissions_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_permissions_raw(handle.read())

    report = build_report(parsed)
    with open("tmp/permissions.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()