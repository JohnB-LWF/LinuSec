# Linux Audit (WSL Ubuntu)

A hybrid **Bash + Python** Linux security audit application designed to run inside **Ubuntu on WSL**.

## Features

- Bash modules collect raw audit data into `tmp/*.txt`
- Python modules parse and score findings into `tmp/*.json`
- `audit.sh` orchestrates full scans and generates timestamped reports in `output/reports/`
- Rich TUI dashboard renders latest report with severity coloring
- Unit tests validate parser behavior using fixture data

## Architecture

- **Bash layer (`modules/*.sh`)**: executes Linux commands, writes raw text files
- **Python layer (`modules/*.py`)**: reads raw files, normalizes findings, applies severity model (`low`, `medium`, `high`)
- **Orchestrator (`audit.sh`)**: runs modules and combines JSON outputs
- **Dashboard (`tui/dashboard.py`)**: visual report viewer using Rich

## Project Structure

```text
linux-audit/
├── audit.sh
├── tmp/
├── modules/
│   ├── system.sh
│   ├── users.sh
│   ├── permissions.sh
│   ├── services.sh
│   ├── network.sh
│   ├── logs.sh
│   ├── system.py
│   ├── users.py
│   ├── permissions.py
│   ├── services.py
│   ├── network.py
│   ├── logs.py
│   └── hardening.py
├── tui/
│   └── dashboard.py
├── tests/
│   ├── test_parsers.py
│   └── sample_raw/
│       ├── system_raw.txt
│       ├── permissions_raw.txt
│       └── logs_raw.txt
├── README.md
├── requirements.txt
└── Makefile
```

## Installation

Inside Ubuntu on WSL:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x audit.sh modules/*.sh
```

## Run the Audit

```bash
make audit
```

or:

```bash
bash audit.sh
```

This writes:

- raw module outputs to `tmp/*.txt`
- parsed module outputs to `tmp/*.json`
- final report to `output/reports/audit-YYYY-MM-DD-HHMMSS.json`

## Run the TUI Dashboard

```bash
make tui
```

The dashboard loads the latest `output/reports/audit-*.json`.

## Run Tests

```bash
make test
```

## Severity Model

- **high**: critical findings or high-risk counts
- **medium**: moderate findings requiring review
- **low**: minimal/no findings

## Example Combined Report (shape)

```json
{
    "generated_at": "2026-01-01T12:00:00+00:00",
    "system": {
        "severity": "medium",
        "metrics": {},
        "examples": []
    },
    "users": {
        "severity": "low",
        "metrics": {},
        "examples": []
    }
}
```