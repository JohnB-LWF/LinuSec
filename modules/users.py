#!/usr/bin/env python3
import json
import re


def parse_sections(raw_text):
    sections = {}
    current = None
    for line in raw_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("__") and stripped.endswith("_START__"):
            current = stripped[len("__") : -len("_START__")]
            sections[current] = []
            continue
        if stripped.startswith("__") and stripped.endswith("_END__"):
            current = None
            continue
        if current is not None:
            if line.strip():
                sections[current].append(line.strip())
    return sections


def parse_users_raw(raw_text):
    sections = parse_sections(raw_text)
    passwd_status = sections.get("PASSWD_STATUS", [])
    uid0_users = sections.get("UID0_USERS", [])
    ssh_settings = sections.get("SSH_SETTINGS", [])

    weak_password_accounts = []
    locked_accounts = []

    for line in passwd_status:
        parts = line.split()
        if len(parts) < 2:
            continue
        username = parts[0]
        status = parts[1].upper()
        if status == "NP":
            weak_password_accounts.append(username)
        if status == "L":
            locked_accounts.append(username)

    merged_settings = {}
    for line in ssh_settings:
        tokens = re.split(r"\s+", line, maxsplit=1)
        if len(tokens) != 2:
            continue
        key = tokens[0].lower()
        value = tokens[1].strip().lower()
        merged_settings[key] = value

    ssh_weaknesses = []
    if merged_settings.get("permitrootlogin", "") in {"yes", "without-password", "prohibit-password"}:
        ssh_weaknesses.append("PermitRootLogin is enabled")
    if merged_settings.get("passwordauthentication", "") == "yes":
        ssh_weaknesses.append("PasswordAuthentication is enabled")
    if merged_settings.get("pubkeyauthentication", "yes") == "no":
        ssh_weaknesses.append("PubkeyAuthentication is disabled")
    if merged_settings.get("challengeresponseauthentication", "no") == "yes":
        ssh_weaknesses.append("ChallengeResponseAuthentication is enabled")

    return {
        "weak_password_accounts": weak_password_accounts,
        "locked_accounts": locked_accounts,
        "uid0_users": uid0_users,
        "ssh_weaknesses": ssh_weaknesses,
    }


def build_report(parsed):
    weak_count = len(parsed["weak_password_accounts"])
    extra_uid0 = max(len(parsed["uid0_users"]) - 1, 0)
    ssh_weakness_count = len(parsed["ssh_weaknesses"])

    severity = "low"
    if weak_count > 0 or extra_uid0 > 0 or ssh_weakness_count >= 2:
        severity = "high"
    elif ssh_weakness_count == 1:
        severity = "medium"

    return {
        "severity": severity,
        "metrics": {
            "weak_password_account_count": weak_count,
            "locked_account_count": len(parsed["locked_accounts"]),
            "uid0_user_count": len(parsed["uid0_users"]),
            "ssh_weakness_count": ssh_weakness_count,
        },
        "examples": {
            "weak_password_accounts": parsed["weak_password_accounts"][:10],
            "uid0_users": parsed["uid0_users"][:10],
            "ssh_weaknesses": parsed["ssh_weaknesses"][:10],
        },
    }


def main():
    with open("tmp/users_raw.txt", "r", encoding="utf-8") as handle:
        parsed = parse_users_raw(handle.read())

    report = build_report(parsed)
    with open("tmp/users.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()
