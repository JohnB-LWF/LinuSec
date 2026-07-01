#!/usr/bin/env python3
import glob
import json
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

SEVERITY_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
}


def severity_text(level):
    color = SEVERITY_COLORS.get(str(level).lower(), "white")
    return Text(str(level).upper(), style=f"bold {color}")


def load_latest_report():
    report_paths = sorted(glob.glob("output/reports/audit-*.json"))
    if not report_paths:
        raise FileNotFoundError("No reports found in output/reports/")

    latest = report_paths[-1]
    with open(latest, "r", encoding="utf-8") as handle:
        return latest, json.load(handle)


def build_summary_panel(report):
    table = Table(expand=True)
    table.add_column("Category", justify="left")
    table.add_column("Severity", justify="center")

    for category, payload in report.items():
        if category == "generated_at":
            continue
        if isinstance(payload, dict) and "severity" in payload:
            table.add_row(category, severity_text(payload["severity"]))

    return Panel(table, title="Audit Summary", border_style="cyan")


def format_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "\n".join(str(item) for item in value[:8]) or "-"
    if isinstance(value, dict):
        return "\n".join(f"{k}: {v}" for k, v in value.items())
    return str(value)


def build_detail_panel(name, payload):
    table = Table(expand=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")

    severity = payload.get("severity", "unknown")
    table.add_row("severity", severity_text(severity))

    metrics = payload.get("metrics", {})
    for key, value in metrics.items():
        table.add_row(f"metrics.{key}", format_value(value))

    examples = payload.get("examples", [])
    table.add_row("examples", format_value(examples))

    border = SEVERITY_COLORS.get(str(severity).lower(), "white")
    return Panel(table, title=name, border_style=border)


def build_layout(report_path, report):
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="summary", size=12),
        Layout(name="details"),
    )

    layout["header"].update(
        Panel(
            Text("Linux Security Audit Dashboard", style="bold cyan"),
            subtitle=Path(report_path).name,
            border_style="cyan",
        )
    )
    layout["summary"].update(build_summary_panel(report))

    detail_layout = Layout()
    detail_panels = []
    for name, payload in report.items():
        if name == "generated_at":
            continue
        if isinstance(payload, dict) and "severity" in payload:
            detail_panels.append(Layout(build_detail_panel(name, payload), size=13))

    if detail_panels:
        detail_layout.split_column(*detail_panels)
    else:
        detail_layout.update(Panel("No module data found in report.", border_style="red"))

    layout["details"].update(detail_layout)
    return layout


def main():
    report_path, report = load_latest_report()
    layout = build_layout(report_path, report)
    console.print(layout)


if __name__ == "__main__":
    main()
