#!/usr/bin/env bash
set -euo pipefail
umask 077

mkdir -p tmp
chmod 700 tmp

SUID_FILES="$(find / -xdev -type f -perm -4000 2>/dev/null || true)"
SGID_FILES="$(find / -xdev -type f -perm -2000 2>/dev/null || true)"
WORLD_WRITABLE_DIRS="$(find / -xdev -type d -perm -0002 2>/dev/null || true)"
HOME_PERMS="$(find /home -mindepth 1 -maxdepth 2 -type d -printf '%m %p\n' 2>/dev/null || true)"

{
    echo "__SUID_START__"
    printf '%s\n' "${SUID_FILES}"
    echo "__SUID_END__"
    echo "__SGID_START__"
    printf '%s\n' "${SGID_FILES}"
    echo "__SGID_END__"
    echo "__WORLD_WRITABLE_DIRS_START__"
    printf '%s\n' "${WORLD_WRITABLE_DIRS}"
    echo "__WORLD_WRITABLE_DIRS_END__"
    echo "__HOME_PERMS_START__"
    printf '%s\n' "${HOME_PERMS}"
    echo "__HOME_PERMS_END__"
} > tmp/permissions_raw.txt
