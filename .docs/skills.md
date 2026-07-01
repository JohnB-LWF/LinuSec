📘 Project Skills & Conventions for AI Assistance

This document defines how the AI should generate code for the Linux Audit Tool project.All generated code must follow these conventions.

🧩 1. Project Architecture

The project is a hybrid Bash + Python application:

Bash modules run system commands and write raw output to tmp/*.txt

Python modules parse raw data, score severity, and write tmp/*.json

audit.sh orchestrates all modules and produces output/reports/audit-*.json

Rich TUI (tui/dashboard.py) loads the latest audit JSON and displays a dashboard

📁 2. Directory Structure

The AI must follow this exact structure:

linux-audit/
├── audit.sh
├── tmp/
├── modules/
│   ├── *.sh
│   ├── *.py
├── tui/
│   └── dashboard.py
├── output/
│   └── reports/
├── tests/
│   ├── test_parsers.py
│   └── sample_raw/
├── README.md
├── requirements.txt
└── Makefile

🧪 3. Bash Module Rules

Each Bash module:

Must write raw output to tmp/*.txt

Must not produce JSON

Must not require user interaction

Must be WSL‑compatible

Must use simple, portable commands

Example pattern:

#!/bin/bash
mkdir -p tmp
COMMAND > tmp/module_raw.txt

🐍 4. Python Module Rules

Each Python module:

Reads raw tmp/*.txt

Parses and normalizes data

Scores severity using:

low | medium | high

Writes JSON to tmp/*.json

Must not run system commands directly (Bash handles that)

Example pattern:

import json

raw = open("tmp/module_raw.txt").read().splitlines()

report = {
    "severity": "medium",
    "parsed_data": raw[:10]
}

json.dump(report, open("tmp/module.json", "w"), indent=4)

🎨 5. Rich TUI Rules

The TUI must:

Load the latest audit-*.json

Display:

Header

Summary panel

Detailed category panels

Use Rich:

Layout

Panel

Table

Color-coded severity

Severity colors:

low = green
medium = yellow
high = red

📊 6. JSON Output Schema

All modules must follow this structure:

{
  "severity": "low|medium|high",
  "metrics": { ... },
  "examples": [ ... ]
}

🧠 7. Severity Scoring Model

The AI must use this scoring model unless told otherwise:

high    = critical findings or large counts
medium  = moderate findings
low     = minimal or no findings

⚙️ 8. Token Optimization Rules

To reduce token usage:

AI should not repeat the directory tree unless asked

AI should not regenerate unchanged modules

AI should generate only the requested file

AI should avoid long explanations unless asked

AI should follow the conventions in this file automatically

🧱 9. Code Style Rules

Bash: POSIX‑compatible, no unnecessary flags

Python: PEP8, functions preferred over inline logic

JSON: pretty‑printed, 4‑space indent

TUI: Rich Layout with Panels and Tables

🚀 10. How the AI Should Respond

When asked to generate a module:

Output only the code file

Follow the conventions above

Do not include commentary unless requested

Do not modify unrelated files

Example request:

“Generate modules/permissions.py”

Expected output:

Only the contents of permissions.py

Following all rules in this skills.md