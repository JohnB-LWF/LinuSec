#!/usr/bin/env bash
set -euo pipefail

mkdir -p tmp

FAILED_LOGINS=""
SUDO_FAILURES=""

if [ -f /var/log/auth.log ]; then
    FAILED_LOGINS="$(grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -n 100 || true)"
    SUDO_FAILURES="$(grep 'sudo' /var/log/auth.log 2>/dev/null | grep 'authentication failure' | tail -n 100 || true)"
elif command -v journalctl >/dev/null 2>&1; then
    FAILED_LOGINS="$(journalctl --no-pager -n 500 2>/dev/null | grep 'Failed password' | tail -n 100 || true)"
    SUDO_FAILURES="$(journalctl --no-pager -n 500 2>/dev/null | grep 'sudo' | grep 'authentication failure' | tail -n 100 || true)"
fi

KERNEL_ERRORS="$(dmesg --level=err 2>/dev/null | tail -n 100 || true)"

{
    echo "__FAILED_LOGINS_START__"
    printf '%s\n' "${FAILED_LOGINS}"
    echo "__FAILED_LOGINS_END__"
    echo "__SUDO_FAILURES_START__"
    printf '%s\n' "${SUDO_FAILURES}"
    echo "__SUDO_FAILURES_END__"
    echo "__KERNEL_ERRORS_START__"
    printf '%s\n' "${KERNEL_ERRORS}"
    echo "__KERNEL_ERRORS_END__"
} > tmp/logs_raw.txt
