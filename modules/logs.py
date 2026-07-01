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
            sections[current].append(line.rstrip())
    return sections


def parse_logs_raw(raw_text):
    sections = parse_sections(raw_text)
    failed_logins = sections.get("FAILED_LOGINS", [])
    sudo_failures = sections.get("SUDO_FAILURES", [])
    kernel_errors = sections.get("KERNEL_ERRORS", [])

    return {
        "failed_logins": failed_logins,
        "sudo_failures": sudo_failures,
        "kernel_errors": kernel_errors,
    }


def build_report(parsed):
    failed_count = len(parsed["failed_logins"])
    sudo_failed_count = len(parsed["sudo_failures"])
    kernel_error_count = len(parsed["kernel_errors"])

    severity = "low"
    if failed_count > 25 or sudo_failed_count > 10 or kernel_error_count > 20:
        severity = "high"
    elif failed_count > 0 or sudo_failed_count > 0 or kernel_error_count > 0:
        severity = "medium"

    return {
        "severity": severity,
        "metrics": {
            "failed_login_count": failed_count,
            "sudo_failure_count": sudo_failed_count,
            "kernel_error_count": kernel_error_count,
        },
        "examples": {
            "failed_logins": parsed["failed_logins"][:10],
            "sudo_failures": parsed["sudo_failures"][:10],
            "kernel_errors": parsed["kernel_errors"][:10],
        },
    }


def main():
    with open("tmp/logs_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_logs_raw(handle.read())

    report = build_report(parsed)
    with open("tmp/logs.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()
