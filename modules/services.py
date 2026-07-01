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


def parse_services_raw(raw_text):
    sections = parse_sections(raw_text)
    running_services = sections.get("RUNNING_SERVICES", [])
    listening = sections.get("LISTENING_PROCESSES", [])
    cron_jobs = sections.get("CRON_JOBS", [])

    risky_keywords = ("telnet", "ftp", "rsh", "rlogin")
    risky_services = [
        line for line in running_services if any(keyword in line.lower() for keyword in risky_keywords)
    ]

    public_listeners = []
    for line in listening:
        normalized = line.lower()
        if "0.0.0.0:" in normalized or "[::]:" in normalized:
            public_listeners.append(line.strip())

    active_cron_jobs = []
    for line in cron_jobs:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        active_cron_jobs.append(stripped)

    return {
        "running_services": running_services,
        "risky_services": risky_services,
        "public_listeners": public_listeners,
        "active_cron_jobs": active_cron_jobs,
    }


def build_report(parsed):
    risky_service_count = len(parsed["risky_services"])
    public_listener_count = len(parsed["public_listeners"])
    cron_count = len(parsed["active_cron_jobs"])

    severity = "low"
    if risky_service_count > 0 or public_listener_count > 20:
        severity = "high"
    elif public_listener_count > 0 or cron_count > 20:
        severity = "medium"

    return {
        "severity": severity,
        "metrics": {
            "running_service_count": len(parsed["running_services"]),
            "risky_service_count": risky_service_count,
            "public_listener_count": public_listener_count,
            "cron_job_count": cron_count,
        },
        "examples": {
            "risky_services": parsed["risky_services"][:10],
            "public_listeners": parsed["public_listeners"][:10],
            "active_cron_jobs": parsed["active_cron_jobs"][:10],
        },
    }


def main():
    with open("tmp/services_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_services_raw(handle.read())

    report = build_report(parsed)
    with open("tmp/services.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()
