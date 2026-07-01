#!/usr/bin/env bash
set -euo pipefail
umask 077

mkdir -p tmp
chmod 700 tmp

RUNNING_SERVICES=""
if command -v systemctl >/dev/null 2>&1; then
    RUNNING_SERVICES="$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null || echo 'systemctl unavailable in this WSL instance')"
else
    RUNNING_SERVICES="systemctl command not found"
fi

LISTENING_PROCESSES="$(ss -tulnp 2>/dev/null || true)"

CRON_JOBS=""
if [ -f /etc/crontab ]; then
    CRON_JOBS="$(cat /etc/crontab 2>/dev/null || true)"
fi
if [ -d /etc/cron.d ]; then
    CRON_JOBS="${CRON_JOBS}
$(cat /etc/cron.d/* 2>/dev/null || true)"
fi
USER_CRON="$(crontab -l 2>/dev/null || true)"
CRON_JOBS="${CRON_JOBS}
${USER_CRON}"

{
    echo "__RUNNING_SERVICES_START__"
    printf '%s\n' "${RUNNING_SERVICES}"
    echo "__RUNNING_SERVICES_END__"
    echo "__LISTENING_PROCESSES_START__"
    printf '%s\n' "${LISTENING_PROCESSES}"
    echo "__LISTENING_PROCESSES_END__"
    echo "__CRON_JOBS_START__"
    printf '%s\n' "${CRON_JOBS}"
    echo "__CRON_JOBS_END__"
} > tmp/services_raw.txt
