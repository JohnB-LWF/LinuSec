# Project Architecture (High‑Level)

We are building a security audit script for Linux and it should be able to run specifically on WSL (Ubuntu). The audit script will be a hybrid build using Python and Bash Scritps.

## Overview

A script that checks:

- Weak file permissions
- Suspicious cron jobs
- Running services
- Open ports
- Failed logins
- SUID binaries
- World‑writable directories

Output

A color‑coded security report with:

Findings
Severity
Recommended fixes

The audit script will perform checks in these categories:

A. System Information

- OS version
- Kernel version
- Installed updates
- Uptime

B. User & Authentication Security

- Weak passwords (via passwd -S)
- Locked/expired accounts
- Users with UID 0
- SSH configuration weaknesses

C. File & Permission Security

- World‑writable directories
- SUID/SGID binaries
- Suspicious permission changes
- Home directory permissions

D. Services & Processes

- Running services
- Services listening on ports
- Unexpected processes
- Cron jobs

E. Networking & Firewall

- Open ports
- Active connections
- Firewall status (UFW)

F. Logs & Suspicious Activity

- Failed logins
- Repeated sudo failures
- Authentication anomalies
- Kernel errors

G. Hardening Recommendations

- Password policy
- SSH hardening
- File permission fixes
- Service hardening

## Directory Structure

Create a clean project folder:

linux-audit/
├── audit.sh
├── tmp/
│   ├── system.json
│   ├── users.json
│   ├── permissions_raw.txt
│   ├── services_raw.txt
│   ├── network_raw.txt
│   ├── logs_raw.txt
├── modules/
│   ├── system.sh
│   ├── users.sh
│   ├── permissions.sh
│   ├── services.sh
│   ├── network.sh
│   ├── logs.sh
│   ├── hardening.sh
│   ├── system.py
│   ├── users.py
│   ├── permissions.py
│   ├── services.py
│   ├── network.py
│   ├── logs.py
│   └── hardening.py
├── tui/
│   └── dashboard.py
└── output/
    └── reports/

This modular design mirrors real security tooling.

## Core Script Skeleton

Here’s the base structure of audit.sh:

```bash
#!/bin/bash
set -e

REPORT="output/reports/audit-$(date +%F-%H%M).json"
mkdir -p tmp output/reports

run_module() {
    local name="$1"
    echo "[+] Running $name..."
    bash "modules/${name}.sh"
    python3 "modules/${name}.py"
}

run_module system
run_module users
run_module permissions
run_module services
run_module network
run_module logs
python3 modules/hardening.py  # pure Python (uses other JSONs)

# combine all JSON into one report
python3 - << 'EOF' > "$REPORT"
import json, glob

data = {}
for path in glob.glob("tmp/*.json"):
    key = path.split("/")[-1].replace(".json", "")
    with open(path) as f:
        data[key] = json.load(f)

print(json.dumps(data, indent=4))
EOF

echo "[+] Audit complete. Report: $REPORT"
```

### permissions.sh

```bash
#!/bin/bash
mkdir -p tmp

find / -type f -perm -4000 2>/dev/null > tmp/suid.txt
find / -type f -perm -2000 2>/dev/null > tmp/sgid.txt
find / -type d -perm -0002 2>/dev/null > tmp/world_writable_dirs.txt

```

### services.sh

```bash
echo "Running services:"
systemctl list-units --type=service --state=running

echo "Processes listening on ports:"
ss -tulnp
```

### network.sh

```bash
echo "Open ports:"
nmap -sT -p- localhost 2>/dev/null

echo "Active connections:"
ss -tunap
```

### logs.sh

```bash
echo "Failed login attempts:"
grep "Failed password" /var/log/auth.log | tail -n 20

echo "Sudo failures:"
grep "sudo" /var/log/auth.log | grep "authentication failure"

echo "Kernel errors:"
dmesg --level=err | tail -n 20
```

### hardening.sh

```bash
echo "Password policy:"
grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE" /etc/login.defs

echo "SSH hardening suggestions:"
echo "- Disable root login"
echo "- Disable password authentication"
echo "- Use key-based auth"
echo "- Change default SSH port"
echo "- Enable fail2ban"
```

### system.sh

```bash
#!/bin/bash
mkdir -p tmp

HOSTNAME=$(hostname)
OS=$(lsb_release -d 2>/dev/null | cut -f2)
KERNEL=$(uname -r)
UPTIME=$(uptime -p)
UPGRADABLE=$(apt list --upgradable 2>/dev/null | sed '1d')

cat > tmp/system_raw.txt <<EOF
HOSTNAME=$HOSTNAME
OS=$OS
KERNEL=$KERNEL
UPTIME=$UPTIME
UPGRADABLE=$UPGRADABLE
EOF
```

### system.py

```python
import json

raw = {}
with open("tmp/system_raw.txt") as f:
    for line in f:
        if "=" in line:
            k, v = line.strip().split("=", 1)
            raw[k] = v

upgradable = [pkg for pkg in raw.get("UPGRADABLE", "").split("\n") if pkg]

severity = "low"
if len(upgradable) > 20:
    severity = "high"
elif len(upgradable) > 0:
    severity = "medium"

report = {
    "hostname": raw.get("HOSTNAME"),
    "os": raw.get("OS"),
    "kernel": raw.get("KERNEL"),
    "uptime": raw.get("UPTIME"),
    "upgradable_count": len(upgradable),
    "severity": severity,
}

with open("tmp/system.json", "w") as f:
    json.dump(report, f, indent=4)
```

### permissions.py

```python
import json

def read_lines(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []

suid = read_lines("tmp/suid.txt")
sgid = read_lines("tmp/sgid.txt")
world_writable_dirs = read_lines("tmp/world_writable_dirs.txt")

severity = "low"
if len(suid) + len(sgid) > 50 or len(world_writable_dirs) > 50:
    severity = "high"
elif len(suid) + len(sgid) > 10 or len(world_writable_dirs) > 10:
    severity = "medium"

report = {
    "suid_count": len(suid),
    "sgid_count": len(sgid),
    "world_writable_dirs_count": len(world_writable_dirs),
    "severity": severity,
    "examples": {
        "suid": suid[:10],
        "sgid": sgid[:10],
        "world_writable_dirs": world_writable_dirs[:10],
    },
}

with open("tmp/permissions.json", "w") as f:
    json.dump(report, f, indent=4)
```

### logs.py

```python
import json
import re

lines = []
try:
    with open("tmp/logs_raw.txt") as f:
        lines = [l.strip() for l in f]
except FileNotFoundError:
    pass

failed = [l for l in lines if "Failed password" in l]
sudo_fail = [l for l in lines if "sudo" in l and "authentication failure" in l]

severity = "low"
if len(failed) > 50 or len(sudo_fail) > 20:
    severity = "high"
elif len(failed) > 10 or len(sudo_fail) > 5:
    severity = "medium"

report = {
    "failed_logins": len(failed),
    "sudo_failures": len(sudo_fail),
    "severity": severity,
    "examples": {
        "failed_logins": failed[:10],
        "sudo_failures": sudo_fail[:10],
    },
}

with open("tmp/logs.json", "w") as f:
    json.dump(report, f, indent=4)
```

### hardening.py

```python
import json

def load(name):
    try:
        with open(f"tmp/{name}.json") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

system = load("system")
permissions = load("permissions")
logs = load("logs")

recommendations = []

if system.get("upgradable_count", 0) > 0:
    recommendations.append("Apply pending security updates via apt.")

if permissions.get("suid_count", 0) > 20:
    recommendations.append("Review and reduce SUID binaries where possible.")

if logs.get("failed_logins", 0) > 10:
    recommendations.append("Investigate repeated failed logins; consider fail2ban or stricter SSH policy.")

report = {
    "overall_severity": max(
        [system.get("severity", "low"),
         permissions.get("severity", "low"),
         logs.get("severity", "low")],
        key=["low", "medium", "high"].index
    ),
    "recommendations": recommendations,
}

with open("tmp/hardening.json", "w") as f:
    json.dump(report, f, indent=4)
```

## Enhancements (To Make It Portfolio‑Ready)

### Add color output

Use ANSI escape codes for severity levels.

### Add JSON output

Great for SIEM ingestion.

### Add a TUI dashboard

Use Python’s rich or textual.

### Add diffing

Compare today’s audit vs yesterday’s.

### Add auto‑fix mode

Optional flag: --fix  
Applies safe hardening steps automatically.

### Add Windows integration

Python can write results to a shared directory:

/mnt/c/Users/johnb/OneDrive/Documents/AuditReports/

Then PowerShell can:

- Read the JSON
- Display notifications
- Email results
- Trigger follow-up scans

### Rich-Based TUI Dashboard (Python)

It should use Rich, Panels, Tables, and Severity color‑coding to create a clean, professional interface.

tui/dashboard.py

```python
import json
import glob
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

console = Console()

SEVERITY_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red"
}

def load_latest_report():
    files = sorted(glob.glob("output/reports/audit-*.json"))
    if not files:
        console.print("[bold red]No audit reports found.[/bold red]")
        exit(1)
    return json.load(open(files[-1]))

def severity_text(level):
    color = SEVERITY_COLORS.get(level, "white")
    return Text(level.upper(), style=f"bold {color}")

def build_summary(report):
    table = Table(title="Audit Summary", expand=True)
    table.add_column("Category", justify="left")
    table.add_column("Severity", justify="center")

    for key, value in report.items():
        if isinstance(value, dict) and "severity" in value:
            table.add_row(key, severity_text(value["severity"]))

    return Panel(table, title="System Security Overview", border_style="cyan")

def build_category_panel(name, data):
    table = Table(expand=True)
    table.add_column("Field")
    table.add_column("Value")

    for k, v in data.items():
        if k == "severity":
            table.add_row("Severity", severity_text(v))
        elif isinstance(v, list):
            table.add_row(k, "\n".join(v[:10]) or "None")
        else:
            table.add_row(k, str(v))

    return Panel(table, title=f"[bold]{name}[/bold]", border_style="magenta")

def build_layout(report):
    layout = Layout()

    layout.split(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
    )

    layout["header"].update(
        Panel(
            Text("Linux Security Audit Dashboard", style="bold cyan"),
            border_style="cyan"
        )
    )

    body = Layout()
    body.split_row(
        Layout(name="left"),
        Layout(name="right")
    )

    body["left"].update(build_summary(report))

    right_panels = []
    for key, value in report.items():
        if isinstance(value, dict):
            right_panels.append(build_category_panel(key, value))

    # stack panels vertically
    right_layout = Layout()
    right_layout.split(*[Layout(panel, size=15) for panel in right_panels[:4]])

    body["right"].update(right_layout)
    layout["body"].update(body)

    return layout

def main():
    report = load_latest_report()
    layout = build_layout(report)
    console.print(layout)

if __name__ == "__main__":
    main()
```
