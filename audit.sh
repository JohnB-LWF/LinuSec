#!/usr/bin/env bash
set -euo pipefail
umask 077

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

mkdir -p tmp output/reports
chmod 700 tmp output output/reports
REPORT="output/reports/audit-$(date +%F-%H%M%S).json"

run_module() {
    local name="$1"
    echo "[+] Running ${name}.sh"
    bash "modules/${name}.sh"
    echo "[+] Running ${name}.py"
    python3 "modules/${name}.py"
}

run_module system
run_module users
run_module permissions
run_module services
run_module network
run_module logs

echo "[+] Running hardening.py"
python3 modules/hardening.py

python3 - "$REPORT" <<'PY'
import datetime
import json
import os
import sys

report_path = sys.argv[1]
module_order = [
    "system",
    "users",
    "permissions",
    "services",
    "network",
    "logs",
    "hardening",
]

combined = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}

for name in module_order:
    path = os.path.join("tmp", f"{name}.json")
    with open(path, "r", encoding="utf-8") as handle:
        combined[name] = json.load(handle)

with open(report_path, "w", encoding="utf-8") as handle:
    json.dump(combined, handle, indent=4)
PY

echo "[+] Audit complete: ${REPORT}"