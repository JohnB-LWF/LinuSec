# LinuSec - Linux Audit Tool

```bash
----         --------  ----    ---- ----    ---- ------------ ------------ ------------ 
****         ********  *****   **** ****    **** ************ ************ ************ 
----           ----    ------  ---- ----    ---- ----         ----         ---          
****           ****    ************ ****    **** ************ ************ ***          
----           ----    ------------ ----    ---- ------------ ------------ ---          
************   ****    ****  ****** ************        ***** ****         ***          
------------ --------  ----   ----- ------------ ------------ ------------ ------------ 
************ ********  ****    **** ************ ************ ************ ************ 
```

A hybrid **Bash + Python** Linux security audit application designed to run inside **Ubuntu on WSL**.

## Features

- Bash modules collect raw audit data into `tmp/*.txt`
- Python modules parse findings, score severity, and produce `tmp/*.json`
- `audit.sh` orchestrates all modules and generates timestamped combined reports in `output/reports/`
- Rich interactive TUI dashboard with category drill-down, trend analysis, and help
- Full explanation-rich JSON schema: every finding tells you *why* it was rated HIGH/MEDIUM/LOW
- Unit tests validate all parsers with fixture data

## Architecture

```
Bash modules (modules/*.sh)
    └─ collect raw system data → tmp/*_raw.txt

Python modules (modules/*.py)
    └─ parse raw data, score severity, explain findings → tmp/*.json
          fields: severity, risk_score, severity_reason,
                  triggered_rules, thresholds, metrics, examples, remediation

audit.sh  (orchestrator)
    └─ runs all modules → combines JSONs → output/reports/audit-YYYY-MM-DD-HHMMSS.json

tui/dashboard.py  (interactive Rich UI)
    └─ loads latest report → interactive menu with drill-down, trend, help
```

## Project Structure

```text
linux-audit/
├── audit.sh                       # Orchestrator
├── modules/
│   ├── system.sh / system.py      # OS info, pending updates
│   ├── users.sh / users.py        # Accounts, SSH config
│   ├── permissions.sh / permissions.py  # SUID, world-writable, home perms
│   ├── services.sh / services.py  # Services, listeners, cron
│   ├── network.sh / network.py    # Ports, connections, firewall
│   ├── logs.sh / logs.py          # Auth log, sudo failures, dmesg
│   └── hardening.py               # Cross-category summary + remediation
├── tui/
│   └── dashboard.py               # Interactive Rich dashboard
├── tests/
│   ├── test_parsers.py            # Unit tests (18 tests)
│   └── sample_raw/                # Fixture files for tests
├── tmp/                           # Raw .txt and parsed .json (generated)
├── output/reports/                # Combined audit reports (generated)
├── README.md
├── requirements.txt
├── Makefile
└── .devcontainer/devcontainer.json
```

## Installation (Ubuntu on WSL)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x audit.sh modules/*.sh
```

## Run the Audit

```bash
make audit
# or:
bash audit.sh
```

Writes:
- Raw module outputs to `tmp/*_raw.txt`
- Parsed module outputs to `tmp/*.json`
- Final combined report to `output/reports/audit-YYYY-MM-DD-HHMMSS.json`

## Run the Interactive TUI Dashboard

```bash
make tui
# or:
python3 tui/dashboard.py
```

### Dashboard Navigation

| Key | Action |
|-----|--------|
| `1`-`N` | Open category drill-down panel |
| `t` | Trend comparison (current vs previous report) |
| `h` | Help screen with navigation guide |
| `q` | Quit |

### Drill-Down Panel (per category)

Each category shows:
- **Severity badge** — LOW / MEDIUM / HIGH with color coding
- **Risk score bar** — numeric 0–100 mapped to a visual bar
- **Severity reason** — plain-English explanation ("HIGH because insecure_home_dir_count > 0")
- **Triggered rules** — each rule that fired with its actual value
- **Scoring thresholds** — the conditions for each severity level
- **Sample evidence** — first few matching lines from raw data
- **Remediation steps** — numbered, with copyable shell commands and impact description

### Trend View

Compares the current report against the previous one:
- ↓ improved (green) — risk score decreased
- ↑ regressed (red) — risk score increased
- → unchanged (dim)

## Run Tests

```bash
make test
# or:
python3 -m unittest -v tests/test_parsers.py
```

18 tests across 3 parsers (system, permissions, logs).

## JSON Report Schema

Every module produces:

```json
{
  "severity": "low | medium | high",
  "risk_score": 0,
  "severity_reason": "Plain-English explanation of why this severity was assigned.",
  "triggered_rules": ["rule description (actual: value)"],
  "thresholds": {
    "high":   "condition that triggers high",
    "medium": "condition that triggers medium",
    "low":    "condition for low"
  },
  "metrics": { "...": "..." },
  "examples": ["..."],
  "remediation": [
    {
      "description": "What to do",
      "command": "copyable shell command",
      "impact": "Why this fix matters"
    }
  ]
}
```

## Severity & Scoring Model

| Severity | Risk Score | Meaning |
|----------|-----------|---------|
| HIGH     | 67–100    | Critical findings requiring immediate action |
| MEDIUM   | 1–66      | Moderate issues that should be reviewed soon |
| LOW      | 0         | No significant findings |

Severity is determined by rule thresholds first; the risk score is then calibrated within the band for trend tracking and relative comparison.

## Makefile Targets

| Target | Command |
|--------|---------|
| `make install` | Install Python dependencies |
| `make audit` | Run the full audit |
| `make tui` | Launch the interactive dashboard |
| `make test` | Run the unit test suite |
| `make clean` | Remove generated `tmp/` and report files |

## Audit Categories

| Category | What it checks |
|----------|----------------|
| system | OS version, kernel, uptime, pending package updates |
| users | Weak/no passwords, extra UID-0 accounts, SSH misconfigs |
| permissions | SUID/SGID binaries, world-writable dirs, insecure home dirs |
| services | Risky legacy services, public listeners, cron jobs |
| network | Open ports, active connections, UFW firewall status |
| logs | Failed SSH logins, sudo failures, kernel errors |
| hardening | Cross-category summary with prioritised remediation steps |