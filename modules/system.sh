#!/usr/bin/env bash
set -euo pipefail
umask 077

mkdir -p tmp
chmod 700 tmp

HOSTNAME_VALUE="$(hostname 2>/dev/null || echo unknown)"
if [ -f /etc/os-release ]; then
    OS_VALUE="$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
else
    OS_VALUE="$(uname -o 2>/dev/null || echo unknown)"
fi
KERNEL_VALUE="$(uname -r 2>/dev/null || echo unknown)"
UPTIME_VALUE="$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo unknown)"

UPGRADABLE=""
if command -v apt >/dev/null 2>&1; then
    UPGRADABLE="$(apt list --upgradable 2>/dev/null | sed '1d' || true)"
fi

{
    echo "HOSTNAME=${HOSTNAME_VALUE}"
    echo "OS=${OS_VALUE}"
    echo "KERNEL=${KERNEL_VALUE}"
    echo "UPTIME=${UPTIME_VALUE}"
    echo "__UPGRADABLE_START__"
    printf '%s\n' "${UPGRADABLE}"
    echo "__UPGRADABLE_END__"
} > tmp/system_raw.txt
