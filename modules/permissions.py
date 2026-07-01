#!/usr/bin/env python3
import json


def parse_sections(raw_text):
    sections = {}
    current = None
    for line in raw_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("__") and stripped.endswith("_START__"):
            current = stripped[len("__") : -len("_START__")]
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

    severity = "low"
    if world_writable_count > 20 or insecure_home_count > 0:
        severity = "high"
    elif world_writable_count > 0 or (suid_count + sgid_count) > 20:
        severity = "medium"

    return {
        "severity": severity,
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
    }


def main():
    with open("tmp/permissions_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_permissions_raw(handle.read())

    report = build_report(parsed)
    with open("tmp/permissions.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()
