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

    if failed_count > 25 or sudo_failed_count > 10 or kernel_error_count > 20:
        severity = "high"
        risk_score = min(
            100,
            67
            + max(0, failed_count - 25)
            + max(0, sudo_failed_count - 10) * 2
            + max(0, kernel_error_count - 20),
        )
    elif failed_count > 0 or sudo_failed_count > 0 or kernel_error_count > 0:
        severity = "medium"
        risk_score = min(66, failed_count * 2 + sudo_failed_count * 4 + kernel_error_count * 3)
    else:
        severity = "low"
        risk_score = 0

    triggered_rules = []
    if failed_count > 25:
        triggered_rules.append(f"failed_login_count > 25 (actual: {failed_count})")
    elif failed_count > 0:
        triggered_rules.append(f"failed_login_count > 0 (actual: {failed_count})")
    if sudo_failed_count > 10:
        triggered_rules.append(f"sudo_failure_count > 10 (actual: {sudo_failed_count})")
    elif sudo_failed_count > 0:
        triggered_rules.append(f"sudo_failure_count > 0 (actual: {sudo_failed_count})")
    if kernel_error_count > 20:
        triggered_rules.append(f"kernel_error_count > 20 (actual: {kernel_error_count})")
    elif kernel_error_count > 0:
        triggered_rules.append(f"kernel_error_count > 0 (actual: {kernel_error_count})")

    reasons = []
    if failed_count > 0:
        reasons.append(f"{failed_count} failed SSH login attempt(s)")
    if sudo_failed_count > 0:
        reasons.append(f"{sudo_failed_count} sudo authentication failure(s)")
    if kernel_error_count > 0:
        reasons.append(f"{kernel_error_count} kernel error(s) in dmesg")

    if reasons:
        severity_reason = severity.upper() + ": " + "; ".join(reasons) + "."
    else:
        severity_reason = "No failed logins, sudo failures, or kernel errors detected."

    return {
        "severity": severity,
        "risk_score": risk_score,
        "severity_reason": severity_reason,
        "triggered_rules": triggered_rules,
        "thresholds": {
            "high":   "failed_logins > 25 OR sudo_failures > 10 OR kernel_errors > 20  -> risk_score 67-100",
            "medium": "any count > 0                                                    -> risk_score 1-66",
            "low":    "all counts == 0                                                  -> risk_score 0",
        },
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
        "remediation": [
            {
                "description": "Install and configure fail2ban",
                "command": "sudo apt install fail2ban -y && sudo systemctl enable --now fail2ban",
                "impact": "Automatically bans IPs with repeated SSH login failures.",
            },
            {
                "description": "Check recent failed login attempts",
                "command": "grep 'Failed password' /var/log/auth.log | tail -n 20",
                "impact": "Identifies attacking IPs for manual blocking.",
            },
            {
                "description": "Block an offending IP with UFW",
                "command": "sudo ufw deny from <attacker-ip>",
                "impact": "Immediately stops further attempts from that IP.",
            },
            {
                "description": "Review sudo failures",
                "command": "grep 'sudo.*authentication failure' /var/log/auth.log",
                "impact": "Reveals privilege escalation attempts by local users.",
            },
            {
                "description": "Review kernel errors",
                "command": "dmesg --level=err | tail -n 50",
                "impact": "Hardware/driver errors can indicate stability or integrity issues.",
            },
        ],
    }


def main():
    with open("tmp/logs_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_logs_raw(handle.read())

    report = build_report(parsed)
    with open("tmp/logs.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()