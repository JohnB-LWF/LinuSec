#!/usr/bin/env bash
set -euo pipefail
umask 077

mkdir -p tmp
chmod 700 tmp

PASSWD_STATUS=""
if passwd -Sa >/dev/null 2>&1; then
    PASSWD_STATUS="$(passwd -Sa 2>/dev/null || true)"
elif passwd -S -a >/dev/null 2>&1; then
    PASSWD_STATUS="$(passwd -S -a 2>/dev/null || true)"
fi

UID0_USERS="$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null || true)"

SSH_SETTINGS=""
if [ -f /etc/ssh/sshd_config ]; then
    SSH_SETTINGS="$(grep -Ei '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|ChallengeResponseAuthentication)' /etc/ssh/sshd_config 2>/dev/null || true)"
fi

if [ -d /etc/ssh/sshd_config.d ]; then
    EXTRA_SSH_SETTINGS="$(grep -Eih '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|ChallengeResponseAuthentication)' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true)"
    SSH_SETTINGS="${SSH_SETTINGS}
${EXTRA_SSH_SETTINGS}"
fi

{
    echo "__PASSWD_STATUS_START__"
    printf '%s\n' "${PASSWD_STATUS}"
    echo "__PASSWD_STATUS_END__"
    echo "__UID0_USERS_START__"
    printf '%s\n' "${UID0_USERS}"
    echo "__UID0_USERS_END__"
    echo "__SSH_SETTINGS_START__"
    printf '%s\n' "${SSH_SETTINGS}"
    echo "__SSH_SETTINGS_END__"
} > tmp/users_raw.txt
