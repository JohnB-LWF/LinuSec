#!/usr/bin/env python3
import json

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def load_module_report(name):
    path = f"tmp/{name}.json"
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def max_severity(severities):
    highest = "low"
    for level in severities:
        if SEVERITY_ORDER.get(level, 0) > SEVERITY_ORDER[highest]:
            highest = level
    return highest


def build_recommendations(system, users, permissions, services, network, logs):
    recommendations = []

    if system["metrics"]["upgradable_count"] > 0:
        recommendations.append("Apply pending package updates using apt upgrade.")

    if users["metrics"]["weak_password_account_count"] > 0:
        recommendations.append("Lock or remediate accounts without passwords.")
    if users["metrics"]["ssh_weakness_count"] > 0:
        recommendations.append("Harden SSH settings: disable root login and password authentication.")

    if permissions["metrics"]["world_writable_dir_count"] > 0:
        recommendations.append("Review and restrict world-writable directories.")
    if permissions["metrics"]["insecure_home_dir_count"] > 0:
        recommendations.append("Set home directory permissions to 700 or 750.")

    if services["metrics"]["risky_service_count"] > 0:
        recommendations.append("Disable risky legacy services (telnet/ftp/rsh/rlogin).")
    if services["metrics"]["public_listener_count"] > 0:
        recommendations.append("Limit externally exposed listening services.")

    if not network["metrics"]["firewall_active"]:
        recommendations.append("Enable UFW and allow only required ports.")

    if logs["metrics"]["failed_login_count"] > 0:
        recommendations.append("Investigate failed SSH logins and consider fail2ban.")
    if logs["metrics"]["sudo_failure_count"] > 0:
        recommendations.append("Audit sudo failures for privilege abuse attempts.")

    if not recommendations:
        recommendations.append("No major hardening issues detected. Continue routine monitoring.")

    return recommendations


def main():
    system = load_module_report("system")
    users = load_module_report("users")
    permissions = load_module_report("permissions")
    services = load_module_report("services")
    network = load_module_report("network")
    logs = load_module_report("logs")

    module_severities = [
        system["severity"],
        users["severity"],
        permissions["severity"],
        services["severity"],
        network["severity"],
        logs["severity"],
    ]

    recommendations = build_recommendations(
        system=system,
        users=users,
        permissions=permissions,
        services=services,
        network=network,
        logs=logs,
    )

    report = {
        "severity": max_severity(module_severities),
        "metrics": {
            "overall_severity": max_severity(module_severities),
            "recommendation_count": len(recommendations),
        },
        "examples": recommendations,
    }

    with open("tmp/hardening.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()
