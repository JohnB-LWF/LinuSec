#!/usr/bin/env bash
set -euo pipefail

mkdir -p tmp

OPEN_PORTS="$(ss -tuln 2>/dev/null || true)"
ACTIVE_CONNECTIONS="$(ss -tunap 2>/dev/null || true)"

UFW_STATUS=""
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS="$(ufw status 2>&1 || true)"
else
    UFW_STATUS="ufw command not found"
fi

{
    echo "__OPEN_PORTS_START__"
    printf '%s\n' "${OPEN_PORTS}"
    echo "__OPEN_PORTS_END__"
    echo "__ACTIVE_CONNECTIONS_START__"
    printf '%s\n' "${ACTIVE_CONNECTIONS}"
    echo "__ACTIVE_CONNECTIONS_END__"
    echo "__UFW_STATUS_START__"
    printf '%s\n' "${UFW_STATUS}"
    echo "__UFW_STATUS_END__"
} > tmp/network_raw.txt
