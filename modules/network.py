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


def parse_network_raw(raw_text):
    sections = parse_sections(raw_text)
    open_ports_lines = sections.get("OPEN_PORTS", [])
    active_connection_lines = sections.get("ACTIVE_CONNECTIONS", [])
    ufw_lines = sections.get("UFW_STATUS", [])

    open_port_entries = [
        line
        for line in open_ports_lines
        if line.strip() and not line.lower().startswith(("netid", "state", "recv-q", "send-q"))
    ]
    active_connections = [
        line
        for line in active_connection_lines
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

    severity = "low"
    if not parsed["firewall_active"] and open_port_count > 5:
        severity = "high"
    elif open_port_count > 0 or not parsed["firewall_active"]:
        severity = "medium"

    return {
        "severity": severity,
        "metrics": {
            "open_port_count": open_port_count,
            "active_connection_count": active_connection_count,
            "firewall_active": parsed["firewall_active"],
        },
        "examples": {
            "open_ports": parsed["open_ports"][:10],
            "active_connections": parsed["active_connections"][:10],
            "ufw_status": parsed["ufw_lines"][:10],
        },
    }


def main():
    with open("tmp/network_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_network_raw(handle.read())

    report = build_report(parsed)
    with open("tmp/network.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()
