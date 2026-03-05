"""Rich console reporter with colour-coded severity output."""

from __future__ import annotations

import os
from collections import defaultdict
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box
from rich.text import Text

from pci_auditor.models import Finding, ScanResult

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

console = Console(highlight=False, emoji=False)


def _rel(file_path: str) -> str:
    """Return path relative to cwd for brevity, falling back to absolute."""
    try:
        return os.path.relpath(file_path)
    except ValueError:
        return file_path


def print_results(result: ScanResult, fail_on: List[str]) -> None:
    """Print scan results to the console, grouped by severity."""
    total = len(result.findings)

    # Header
    subtitle = (
        f"{total} finding{'s' if total != 1 else ''}"
        f" · {result.scanned_files} file{'s' if result.scanned_files != 1 else ''}"
        f" · {result.scanned_lines:,} lines"
    )
    console.print()
    console.print(
        Panel(
            f"[bold]PCI DSS 4.0 Compliance Scan Results[/bold]\n[dim]{subtitle}[/dim]",
            border_style="red" if total else "green",
            expand=False,
        )
    )
    console.print()

    if not result.findings:
        console.print("[bold green]  OK  No PCI DSS violations found.[/bold green]")
        console.print()
        _print_summary(result)
        return

    # Group by severity
    by_severity: dict = defaultdict(list)
    for f in result.findings:
        by_severity[f.severity.lower()].append(f)

    for severity in _SEVERITY_ORDER:
        findings = by_severity.get(severity, [])
        if not findings:
            continue

        style = _SEVERITY_STYLES[severity]
        label = _SEVERITY_LABELS[severity]
        count = len(findings)

        # Section rule line
        console.print(
            Rule(
                f"[{style}] {label} [/{style}][dim]  {count} finding{'s' if count != 1 else ''}[/dim]",
                style="dim",
                align="left",
            )
        )
        console.print()

        # Sort within severity: by file then line
        for finding in sorted(findings, key=lambda f: (f.file_path, f.line_number)):
            _print_finding(finding, style)

    _print_summary(result)

    # Pass / fail banner
    fail_set = {s.lower() for s in fail_on}
    has_blocking = any(f.severity.lower() in fail_set for f in result.findings)
    console.print()
    if has_blocking:
        console.print(
            Panel(
                f"[bold red]FAIL  Build blocked"
                f" — {result.critical_count} critical, {result.high_count} high"
                f" violation{'s' if result.critical_count + result.high_count != 1 else ''} found[/bold red]",
                border_style="red",
                expand=False,
            )
        )
    else:
        console.print(
            Panel(
                "[bold green]PASS  No blocking violations (critical/high).[/bold green]",
                border_style="green",
                expand=False,
            )
        )


def _print_finding(finding: Finding, severity_style: str) -> None:
    source_badge = "[dim][AI][/dim]" if finding.source == "ai" else "[dim][pattern][/dim]"
    rel_path = _rel(finding.file_path)

    # Header line: Rule · file:line  [source]
    console.print(
        f"  [{severity_style}]Rule {finding.rule_id}[/{severity_style}]"
        f"  [dim]·[/dim]  [bold white]{rel_path}[/bold white]"
        f"[dim]:{finding.line_number}[/dim]"
        f"  {source_badge}"
    )

    # Description — skip the generic pattern boilerplate prefix
    desc = finding.description
    if desc.startswith(f"[Rule {finding.rule_id}]"):
        desc = desc[len(f"[Rule {finding.rule_id}]"):].strip()
    console.print(f"  [white]{desc}[/white]")

    # Snippet
    if finding.snippet:
        snippet = finding.snippet.strip()[:120]
        console.print(f"  [dim]│  {snippet}[/dim]")

    # Fix
    if finding.recommendation:
        rec = finding.recommendation
        # Strip generic prefix if present
        if rec.startswith(f"Review this line against PCI DSS {finding.rule_id}."):
            pass  # keep it — it's the full recommendation
        console.print(f"  [green]└─ Fix:[/green] {rec}")

    console.print()


def _print_summary(result: ScanResult) -> None:
    table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
    table.add_column("Severity", style="bold", min_width=12)
    table.add_column("Count", justify="right", min_width=6)

    def _row(label: str, count: int, style: str) -> None:
        if count:
            table.add_row(f"[{style}]{label}[/{style}]", f"[{style}]{count}[/{style}]")
        else:
            table.add_row(f"[dim]{label}[/dim]", "[dim]0[/dim]")

    _row("Critical", result.critical_count, "bold red")
    _row("High",     result.high_count,     "bold yellow")
    _row("Medium",   result.medium_count,   "yellow")
    _row("Low",      result.low_count,      "cyan")
    table.add_section()
    table.add_row("[dim]Total findings[/dim]", f"[dim]{len(result.findings)}[/dim]")
    table.add_row("[dim]Files scanned[/dim]",  f"[dim]{result.scanned_files}[/dim]")
    table.add_row("[dim]Lines scanned[/dim]",  f"[dim]{result.scanned_lines:,}[/dim]")

    console.print(table)

    if result.errors:
        console.print("[yellow]Warnings during scan:[/yellow]")
        for err in result.errors:
            console.print(f"  [yellow]• {err}[/yellow]")

