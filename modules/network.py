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


def parse_network_raw(raw_text):
    sections = parse_sections(raw_text)
    open_ports_lines = sections.get("OPEN_PORTS", [])
    active_connection_lines = sections.get("ACTIVE_CONNECTIONS", [])
    ufw_lines = sections.get("UFW_STATUS", [])

    open_port_entries = [
        line for line in open_ports_lines
        if line.strip() and not line.lower().startswith(("netid", "state", "recv-q", "send-q"))
    ]
    active_connections = [
        line for line in active_connection_lines
        if line.strip() and not line.lower().startswith(("netid", "state", "recv-q", "send-q"))
    ]
    ufw_status_text = " ".join(ufw_lines).lower()
    firewall_active = "status: active" in ufw_status_text

    return {
        "open_ports": open_port_entries,
        "active_connections": active_connections,
        "firewall_active": firewall_active,
        "ufw_lines": ufw_lines,
    }


def build_report(parsed):
    open_port_count = len(parsed["open_ports"])
    active_connection_count = len(parsed["active_connections"])
    firewall_active = parsed["firewall_active"]

    if not firewall_active and open_port_count > 5:
        severity = "high"
        risk_score = min(100, 67 + open_port_count * 2)
    elif open_port_count > 0 or not firewall_active:
        severity = "medium"
        risk_score = min(66, 20 + open_port_count * 5 + (20 if not firewall_active else 0))
    else:
        severity = "low"
        risk_score = 0

    triggered_rules = []
    if not firewall_active:
        triggered_rules.append("firewall (UFW) is inactive or not installed")
    if not firewall_active and open_port_count > 5:
        triggered_rules.append(f"open_port_count > 5 with no firewall (actual: {open_port_count})")
    elif open_port_count > 0:
        triggered_rules.append(f"open_port_count > 0 (actual: {open_port_count})")

    reasons = []
    if not firewall_active:
        reasons.append("firewall (UFW) is inactive")
    if open_port_count > 0:
        reasons.append(f"{open_port_count} open port(s) detected")

    if reasons:
        severity_reason = severity.upper() + ": " + "; ".join(reasons) + "."
    else:
        severity_reason = "Firewall is active and no unexpected open ports detected."

    return {
        "severity": severity,
        "risk_score": risk_score,
        "severity_reason": severity_reason,
        "triggered_rules": triggered_rules,
        "thresholds": {
            "high":   "firewall inactive AND open_ports > 5  -> risk_score 67-100",
            "medium": "open_ports > 0 OR firewall inactive   -> risk_score 1-66",
            "low":    "firewall active AND open_ports == 0   -> risk_score 0",
        },
        "metrics": {
            "open_port_count": open_port_count,
            "active_connection_count": active_connection_count,
            "firewall_active": firewall_active,
        },
        "examples": {
            "open_ports": parsed["open_ports"][:10],
            "active_connections": parsed["active_connections"][:10],
            "ufw_status": parsed["ufw_lines"][:10],
        },
        "remediation": [
            {
                "description": "Enable UFW firewall",
                "command": "sudo ufw enable",
                "impact": "Activates the firewall to block unauthorised inbound connections.",
            },
            {
                "description": "Set a default deny policy",
                "command": "sudo ufw default deny incoming && sudo ufw default allow outgoing",
                "impact": "Blocks all inbound traffic except explicitly allowed ports.",
            },
            {
                "description": "Allow only required ports (example: SSH)",
                "command": "sudo ufw allow 22/tcp",
                "impact": "Opens only the ports your services actually need.",
            },
            {
                "description": "Review current UFW rules",
                "command": "sudo ufw status verbose",
                "impact": "Audits which ports are currently open and to whom.",
            },
            {
                "description": "List all open ports and associated processes",
                "command": "ss -tulnp",
                "impact": "Identifies unexpected services that may be listening.",
            },
        ],
    }


def main():
    with open("tmp/network_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_network_raw(handle.read())

    report = build_report(parsed)
    with open("tmp/network.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()