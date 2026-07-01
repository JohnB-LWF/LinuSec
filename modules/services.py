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
            sections[current].append(line.rstrip())
    return sections


def parse_services_raw(raw_text):
    sections = parse_sections(raw_text)
    running_services = sections.get("RUNNING_SERVICES", [])
    listening = sections.get("LISTENING_PROCESSES", [])
    cron_jobs = sections.get("CRON_JOBS", [])

    risky_keywords = ("telnet", "ftp", "rsh", "rlogin")
    risky_services = [
        line for line in running_services
        if any(keyword in line.lower() for keyword in risky_keywords)
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

    if risky_service_count > 0 or public_listener_count > 20:
        severity = "high"
        risk_score = min(100, 67 + risky_service_count * 10 + max(0, public_listener_count - 20) * 2)
    elif public_listener_count > 0 or cron_count > 20:
        severity = "medium"
        risk_score = min(66, 1 + public_listener_count * 5 + max(0, cron_count - 20) * 2)
    else:
        severity = "low"
        risk_score = 0

    triggered_rules = []
    if risky_service_count > 0:
        triggered_rules.append(
            f"risky_service_count > 0 (actual: {risky_service_count}) — telnet/ftp/rsh/rlogin detected"
        )
    if public_listener_count > 20:
        triggered_rules.append(f"public_listener_count > 20 (actual: {public_listener_count})")
    elif public_listener_count > 0:
        triggered_rules.append(f"public_listener_count > 0 (actual: {public_listener_count})")
    if cron_count > 20:
        triggered_rules.append(f"active_cron_job_count > 20 (actual: {cron_count})")

    reasons = []
    if risky_service_count > 0:
        reasons.append(f"{risky_service_count} risky legacy service(s) running")
    if public_listener_count > 0:
        reasons.append(f"{public_listener_count} service(s) listening on all interfaces")
    if cron_count > 20:
        reasons.append(f"{cron_count} active cron jobs (elevated count)")

    if reasons:
        severity_reason = severity.upper() + ": " + "; ".join(reasons) + "."
    else:
        severity_reason = "No risky services or unexpected listeners detected."

    return {
        "severity": severity,
        "risk_score": risk_score,
        "severity_reason": severity_reason,
        "triggered_rules": triggered_rules,
        "thresholds": {
            "high":   "risky_service_count > 0 OR public_listeners > 20  -> risk_score 67-100",
            "medium": "public_listeners > 0 OR cron_jobs > 20            -> risk_score 1-66",
            "low":    "none of the above                                  -> risk_score 0",
        },
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
        "remediation": [
            {
                "description": "Disable telnet service",
                "command": "sudo systemctl disable --now telnet.socket",
                "impact": "Telnet transmits credentials in plain text; replace with SSH.",
            },
            {
                "description": "Disable FTP service",
                "command": "sudo systemctl disable --now vsftpd",
                "impact": "FTP is unencrypted; use SFTP or FTPS instead.",
            },
            {
                "description": "Review services listening on all interfaces",
                "command": "ss -tulnp | grep -E '0\\.0\\.0\\.0|:::'",
                "impact": "Services bound to 0.0.0.0/[::] are reachable from any network.",
            },
            {
                "description": "Review all active cron jobs",
                "command": "crontab -l; cat /etc/cron.d/* 2>/dev/null",
                "impact": "Unexpected cron jobs may indicate persistence mechanisms.",
            },
        ],
    }


def main():
    with open("tmp/services_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_services_raw(handle.read())

    report = build_report(parsed)
    with open("tmp/services.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()