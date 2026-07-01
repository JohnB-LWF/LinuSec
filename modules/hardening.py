#!/usr/bin/env python3
import json

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def load_module_report(name):
    path = f"tmp/{name}.json"
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def max_severity(severities):
    highest = "low"
    for level in severities:
        if SEVERITY_ORDER.get(level, 0) > SEVERITY_ORDER[highest]:
            highest = level
    return highest


def main():
    module_names = ["system", "users", "permissions", "services", "network", "logs"]
    modules = {name: load_module_report(name) for name in module_names}

    severities = [m["severity"] for m in modules.values()]
    scores = [m.get("risk_score", 0) for m in modules.values()]
    overall_severity = max_severity(severities)
    overall_risk_score = max(scores) if scores else 0

    high_cats = [n for n, m in modules.items() if m["severity"] == "high"]
    medium_cats = [n for n, m in modules.items() if m["severity"] == "medium"]
    low_cats = [n for n, m in modules.items() if m["severity"] == "low"]
    priority_order = high_cats + medium_cats + low_cats

    # Collect all triggered rules across modules
    all_triggered_rules = []
    for name, report in modules.items():
        for rule in report.get("triggered_rules", []):
            all_triggered_rules.append(f"{name}: {rule}")

    # Build per-category remediation list (top 2 steps per module, high-severity first)
    top_remediation = []
    for name in priority_order:
        report = modules[name]
        for step in report.get("remediation", [])[:2]:
            top_remediation.append({
                "category": name,
                "description": step.get("description", ""),
                "command": step.get("command", ""),
                "impact": step.get("impact", ""),
            })

    if not all_triggered_rules:
        severity_reason = "All categories scored low. No significant issues detected. Continue routine monitoring."
    else:
        top_cats = ", ".join(
            f"{n} ({modules[n].get('severity', 'low')})" for n in priority_order[:3]
        )
        severity_reason = (
            f"Overall {overall_severity.upper()} driven by: {top_cats}."
        )

    report = {
        "severity": overall_severity,
        "risk_score": overall_risk_score,
        "severity_reason": severity_reason,
        "triggered_rules": all_triggered_rules,
        "thresholds": {
            "high":   "any module severity == high",
            "medium": "any module severity == medium (and none high)",
            "low":    "all modules severity == low",
        },
        "metrics": {
            "overall_risk_score": overall_risk_score,
            "highest_risk_category": priority_order[0] if priority_order else "none",
            "categories_at_high": len(high_cats),
            "categories_at_medium": len(medium_cats),
            "categories_at_low": len(low_cats),
            "recommendation_count": len(top_remediation),
        },
        "examples": [r["description"] for r in top_remediation[:10]],
        "remediation": top_remediation,
    }

    with open("tmp/hardening.json", "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=4)


if __name__ == "__main__":
    main()