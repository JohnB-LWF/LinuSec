#!/usr/bin/env python3
"""
Interactive Rich-based Linux Security Audit Dashboard.

Navigation
----------
  1-N   Drill into a specific category
  t     Trend comparison (current vs previous report)
  h     Help screen
  q     Quit
"""
import glob
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()

SEVERITY_COLORS: Dict[str, str] = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
}

RISK_BAR_WIDTH = 24

CATEGORY_DESCRIPTIONS: Dict[str, str] = {
    "system":      "OS version, kernel, uptime, and pending package updates.",
    "users":       "User accounts, password status, UID-0 accounts, SSH config weaknesses.",
    "permissions": "SUID/SGID binaries, world-writable dirs, insecure home dir permissions.",
    "services":    "Running services, public listeners, cron jobs, risky legacy services.",
    "network":     "Open ports, active connections, firewall (UFW) status.",
    "logs":        "Failed SSH logins, sudo failures, kernel errors from dmesg.",
    "hardening":   "Cross-category risk summary with prioritised remediation steps.",
}


# ─── Data Loading ─────────────────────────────────────────────────────────────

def load_reports() -> Tuple[str, dict, Optional[dict]]:
    paths = sorted(glob.glob("output/reports/audit-*.json"))
    if not paths:
        console.print("[bold red]No audit reports found in output/reports/.[/bold red]")
        console.print("Run [bold cyan]make audit[/bold cyan] or [bold cyan]bash audit.sh[/bold cyan] first.")
        sys.exit(1)

    current_path = paths[-1]
    with open(current_path, "r", encoding="utf-8") as fh:
        current = json.load(fh)

    previous: Optional[dict] = None
    if len(paths) >= 2:
        with open(paths[-2], "r", encoding="utf-8") as fh:
            previous = json.load(fh)

    return current_path, current, previous


def get_categories(report: dict) -> List[Tuple[str, dict]]:
    return [
        (name, payload)
        for name, payload in report.items()
        if name != "generated_at" and isinstance(payload, dict) and "severity" in payload
    ]


# ─── Rich Helpers ─────────────────────────────────────────────────────────────

def severity_badge(level: str) -> Text:
    color = SEVERITY_COLORS.get(str(level).lower(), "white")
    return Text(f" {str(level).upper()} ", style=f"bold white on {color}")


def risk_bar(score: int) -> Text:
    score = max(0, min(100, int(score)))
    filled = round((score / 100) * RISK_BAR_WIDTH)
    bar = "█" * filled + "░" * (RISK_BAR_WIDTH - filled)
    if score >= 67:
        color = "red"
    elif score > 0:
        color = "yellow"
    else:
        color = "green"
    return Text(f"{bar} {score:>3}/100", style=color)


def trend_indicator(cur: int, prev: Optional[int]) -> Text:
    if prev is None:
        return Text("─ first run", style="dim")
    delta = cur - prev
    if delta < 0:
        return Text(f"↓ {abs(delta):>3}  improved", style="green")
    elif delta > 0:
        return Text(f"↑ {delta:>3}  regressed", style="red")
    return Text("→ no change", style="dim")


def fmt_examples(examples) -> str:
    if isinstance(examples, list):
        lines = [str(e) for e in examples[:8]]
        return "\n".join(lines) if lines else "-"
    if isinstance(examples, dict):
        out = []
        for key, items in examples.items():
            if isinstance(items, list) and items:
                out.append(f"[bold]{key}:[/bold]")
                out.extend(f"  {item}" for item in items[:4])
        return "\n".join(out) if out else "-"
    return str(examples)


# ─── Screen: Summary ──────────────────────────────────────────────────────────

def print_header(report_path: str, report: dict) -> None:
    generated_at = report.get("generated_at", "unknown")
    console.print(
        Panel(
            Text("  Linux Security Audit Dashboard", style="bold cyan", justify="center"),
            subtitle=f"[dim]{Path(report_path).name}   {generated_at}[/dim]",
            border_style="cyan",
        )
    )


def print_summary(report: dict, previous: Optional[dict]) -> None:
    categories = get_categories(report)

    table = Table(
        title="Audit Summary",
        box=box.ROUNDED,
        expand=True,
        show_lines=True,
        border_style="cyan",
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Category", style="bold", min_width=12)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Risk Score", min_width=30)
    table.add_column("Trend", min_width=18)

    for idx, (name, payload) in enumerate(categories, start=1):
        score = payload.get("risk_score", 0)
        prev_score: Optional[int] = None
        if previous and name in previous and isinstance(previous[name], dict):
            prev_score = previous[name].get("risk_score")

        table.add_row(
            str(idx),
            name,
            severity_badge(payload.get("severity", "low")),
            risk_bar(score),
            trend_indicator(score, prev_score),
        )

    console.print(table)


# ─── Screen: Detail ───────────────────────────────────────────────────────────

def print_detail(name: str, payload: dict) -> None:
    severity = payload.get("severity", "low")
    score = payload.get("risk_score", 0)
    reason = payload.get("severity_reason", "No explanation available.")
    triggered = payload.get("triggered_rules", [])
    thresholds = payload.get("thresholds", {})
    examples = payload.get("examples", [])
    metrics = payload.get("metrics", {})
    remediation = payload.get("remediation", [])
    border = SEVERITY_COLORS.get(str(severity).lower(), "white")

    console.print()
    console.rule(f"[bold]{name.upper()}[/bold]", style="cyan")
    console.print()

    # ── Overview
    overview = Table.grid(expand=True, padding=(0, 2))
    overview.add_column("Label", style="bold", width=16)
    overview.add_column("Value")
    overview.add_row("Severity:", severity_badge(severity))
    overview.add_row("Risk Score:", risk_bar(score))
    overview.add_row("Reason:", Text(reason, style="italic"))
    console.print(Panel(overview, title="Overview", border_style=border))

    # ── Metrics
    if metrics:
        m_table = Table(box=box.SIMPLE, expand=True)
        m_table.add_column("Metric", style="bold cyan")
        m_table.add_column("Value")
        for k, v in metrics.items():
            m_table.add_row(k, str(v))
        console.print(Panel(m_table, title="Metrics", border_style="blue"))

    # ── Triggered Rules
    if triggered:
        r_table = Table(box=box.SIMPLE, expand=True, show_header=False)
        r_table.add_column("Rule")
        for rule in triggered:
            r_table.add_row(f"[bold red]✗[/bold red]  {rule}")
        console.print(Panel(r_table, title="Triggered Rules", border_style="red"))
    else:
        console.print(Panel(
            "[bold green]✔  No rules triggered — this category is clean.[/bold green]",
            title="Triggered Rules",
            border_style="green",
        ))

    # ── Thresholds
    if thresholds:
        t_table = Table(box=box.SIMPLE, expand=True)
        t_table.add_column("Level", style="bold", width=10)
        t_table.add_column("Condition")
        for level, condition in thresholds.items():
            color = SEVERITY_COLORS.get(level, "white")
            t_table.add_row(Text(level.upper(), style=f"bold {color}"), condition)
        console.print(Panel(t_table, title="Scoring Thresholds", border_style="yellow"))

    # ── Evidence
    evidence_text = fmt_examples(examples)
    if evidence_text and evidence_text != "-":
        console.print(Panel(evidence_text, title="Sample Evidence", border_style="magenta"))
    else:
        console.print(Panel("[dim]No evidence samples in this report.[/dim]", title="Sample Evidence", border_style="magenta"))

    # ── Remediation
    if remediation:
        lines = []
        for i, step in enumerate(remediation, start=1):
            desc = step.get("description", "")
            cmd = step.get("command", "")
            impact = step.get("impact", "")
            lines.append(f"[bold white]{i}. {desc}[/bold white]")
            if cmd:
                lines.append(f"   [bold green]$[/bold green] [cyan]{cmd}[/cyan]")
            if impact:
                lines.append(f"   [dim italic]{impact}[/dim italic]")
            lines.append("")
        console.print(Panel("\n".join(lines).rstrip(), title="Remediation Steps", border_style="green"))
    else:
        console.print(Panel("[dim]No remediation steps available.[/dim]", title="Remediation Steps", border_style="green"))

    console.print()


# ─── Screen: Trend ────────────────────────────────────────────────────────────

def print_trend(report: dict, previous: Optional[dict]) -> None:
    if previous is None:
        console.print(Panel(
            "[yellow]No previous report found. Run the audit again to enable trend comparison.[/yellow]",
            title="Trend Analysis",
            border_style="yellow",
        ))
        return

    categories = get_categories(report)
    table = Table(title="Trend Analysis", box=box.ROUNDED, expand=True, show_lines=True)
    table.add_column("Category", style="bold", min_width=12)
    table.add_column("Prev Severity", justify="center", width=12)
    table.add_column("Cur Severity", justify="center", width=12)
    table.add_column("Prev Score", justify="center", width=11)
    table.add_column("Cur Score", justify="center", width=11)
    table.add_column("Delta", justify="center", width=14)
    table.add_column("Status", justify="center", width=12)

    for name, payload in categories:
        cur_score = payload.get("risk_score", 0)
        cur_sev = payload.get("severity", "low")
        prev_payload = previous.get(name, {})
        if isinstance(prev_payload, dict):
            prev_score = prev_payload.get("risk_score")
            prev_sev = prev_payload.get("severity", "unknown")
        else:
            prev_score = None
            prev_sev = "unknown"

        if prev_score is None:
            delta_text = Text("─ new", style="dim")
            status_text = Text("NEW", style="bold blue")
        else:
            delta = cur_score - prev_score
            if delta < 0:
                delta_text = Text(f"↓ {abs(delta)}", style="green")
                status_text = Text("IMPROVED", style="bold green")
            elif delta > 0:
                delta_text = Text(f"↑ {delta}", style="red")
                status_text = Text("REGRESSED", style="bold red")
            else:
                delta_text = Text("±0", style="dim")
                status_text = Text("UNCHANGED", style="dim")

        prev_score_str = str(prev_score) if prev_score is not None else "─"
        table.add_row(
            name,
            severity_badge(prev_sev) if prev_sev != "unknown" else Text("─", style="dim"),
            severity_badge(cur_sev),
            prev_score_str,
            str(cur_score),
            delta_text,
            status_text,
        )

    prev_ts = previous.get("generated_at", "unknown")
    cur_ts = report.get("generated_at", "unknown")
    console.print(Panel(
        table,
        subtitle=f"[dim]Previous: {prev_ts}  →  Current: {cur_ts}[/dim]",
        border_style="blue",
    ))


# ─── Screen: Help ─────────────────────────────────────────────────────────────

def print_help(num_categories: int) -> None:
    lines = [
        "[bold cyan]Navigation[/bold cyan]",
        f"  [bold]1-{num_categories}[/bold]  Select a category to view the drill-down detail panel",
        "  [bold]t[/bold]     Show trend comparison between current and previous report",
        "  [bold]h[/bold]     Show this help screen",
        "  [bold]q[/bold]     Quit the dashboard",
        "",
        "[bold cyan]Severity Levels[/bold cyan]",
        f"  {severity_badge('high').__str__():<10}  Critical findings — remediate immediately",
        f"  {severity_badge('medium').__str__():<10}  Moderate issues — review soon",
        f"  {severity_badge('low').__str__():<10}  Minimal or no findings — continue monitoring",
        "",
        "[bold cyan]Risk Score[/bold cyan]",
        "  A numeric value 0-100 computed from weighted rule matches.",
        "  HIGH >= 67  |  MEDIUM 1-66  |  LOW = 0",
        "  Each module's score thresholds are shown in its detail view.",
        "",
        "[bold cyan]Category Descriptions[/bold cyan]",
    ]
    for cat, desc in CATEGORY_DESCRIPTIONS.items():
        lines.append(f"  [bold]{cat:<14}[/bold] {desc}")

    lines += [
        "",
        "[bold cyan]Re-running the Audit[/bold cyan]",
        "  [cyan]$ make audit[/cyan]            # or: bash audit.sh",
        "  [cyan]$ make tui[/cyan]              # or: python3 tui/dashboard.py",
        "",
        "[bold cyan]Running Unit Tests[/bold cyan]",
        "  [cyan]$ make test[/cyan]             # or: python3 -m unittest -v tests/test_parsers.py",
        "",
        "[bold cyan]Report Location[/bold cyan]",
        "  Reports are saved to [cyan]output/reports/audit-YYYY-MM-DD-HHMMSS.json[/cyan]",
        "  The dashboard always loads the [bold]most recent[/bold] report.",
    ]

    console.print(Panel(
        "\n".join(lines),
        title="Help",
        border_style="cyan",
    ))


# ─── Main Loop ────────────────────────────────────────────────────────────────

def main() -> None:
    report_path, report, previous = load_reports()
    categories = get_categories(report)
    num_categories = len(categories)

    while True:
        console.clear()
        print_header(report_path, report)
        print_summary(report, previous)
        console.print()

        choice = Prompt.ask(
            f"[bold]Select[/bold] [dim]category 1-{num_categories}[/dim] | "
            "[bold]t[/bold][dim]=trend[/dim]  "
            "[bold]h[/bold][dim]=help[/dim]  "
            "[bold]q[/bold][dim]=quit[/dim]"
        ).strip().lower()

        if choice == "q":
            console.print("[dim]Goodbye.[/dim]")
            break

        if choice == "h":
            console.clear()
            print_help(num_categories)
            Prompt.ask("\n[dim]Press Enter to return[/dim]")
            continue

        if choice == "t":
            console.clear()
            print_trend(report, previous)
            Prompt.ask("\n[dim]Press Enter to return[/dim]")
            continue

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < num_categories:
                cat_name, cat_payload = categories[idx]
                console.clear()
                print_detail(cat_name, cat_payload)
                Prompt.ask("[dim]Press Enter to return to summary[/dim]")
                continue

        console.print(
            f"[yellow]Unknown option '{choice}'. Enter a number 1-{num_categories}, 't', 'h', or 'q'.[/yellow]"
        )
        Prompt.ask("[dim]Press Enter to continue[/dim]")


if __name__ == "__main__":
    main()