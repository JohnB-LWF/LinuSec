I am building a complete hybrid Linux Security Audit application inside Ubuntu on WSL. 
Generate the entire project structure, all code files, and all supporting documentation.

The architecture must follow this exact design:

====================================================
PROJECT OVERVIEW
====================================================

A hybrid Bash + Python security auditing tool with:

1. Bash modules that run Linux system commands and save raw output into tmp/*.txt
2. Python modules that parse the raw data, score severity, and output tmp/*.json
3. A main Bash orchestrator script (audit.sh) that runs all modules and produces output/reports/audit-*.json
4. A Rich-based Python TUI (tui/dashboard.py) that loads the latest audit-*.json and displays:
   - A summary panel with severity levels
   - Detailed panels for each audit category
   - Rich Layout, Panels, Tables, and color-coded severity

The tool must run fully inside Ubuntu on WSL.

====================================================
DIRECTORY STRUCTURE
====================================================

Generate the full directory tree:

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

====================================================
BASH MODULE REQUIREMENTS
====================================================

Each Bash module must:

- Run relevant Linux commands
- Save raw output into tmp/*.txt
- Avoid interactive prompts
- Work inside WSL Ubuntu

Modules to generate:

system.sh
users.sh
permissions.sh
services.sh
network.sh
logs.sh

====================================================
PYTHON MODULE REQUIREMENTS
====================================================

Each Python module must:

- Read the raw tmp/*.txt files
- Parse and normalize the data
- Score severity using a consistent scoring model:
  severity = low | medium | high
- Output tmp/*.json files

Modules to generate:

system.py
users.py
permissions.py
services.py
network.py
logs.py
hardening.py (reads all JSON files and generates recommendations)

====================================================
MAIN ORCHESTRATOR SCRIPT
====================================================

Generate audit.sh that:

- Creates tmp/ and output/reports/
- Runs each Bash module
- Runs each Python module
- Combines all tmp/*.json files into a single output/reports/audit-*.json

====================================================
RICH TUI DASHBOARD
====================================================

Generate tui/dashboard.py that:

- Loads the latest audit-*.json
- Displays a Rich-based dashboard with:
  - Header panel
  - Summary panel showing severity per category
  - Detailed panels for each category
  - Color-coded severity using Rich Text
  - Rich Layout, Panels, Tables

====================================================
ADDITIONAL REQUIREMENTS
====================================================

Generate:

1. README.md with:
   - Installation instructions
   - How to run the audit
   - How to run the TUI
   - Architecture explanation
   - Example output

2. requirements.txt including:
   - rich
   - any other Python dependencies

3. Makefile with:
   - make audit
   - make tui
   - make clean

4. tests/test_parsers.py with:
   - Unit tests for Python parsing modules
   - Use sample_raw/*.txt as fixtures

5. Optional: devcontainer.json for VS Code Dev Containers

====================================================
OUTPUT FORMAT
====================================================

Produce everything in one response:

- Directory tree
- All Bash scripts
- All Python scripts
- README.md
- requirements.txt
- Makefile
- tests
- devcontainer.json (optional)

All code must be runnable inside Ubuntu on WSL.

====================================================

Generate the full project now.
