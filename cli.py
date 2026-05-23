#!/usr/bin/env python3
"""
Web Cache Deception Detector — CLI
Usage:
    python cli.py https://example.com
    python cli.py discord.com github.com vercel.com
"""

import sys
import time
import threading
from scanner import scan, ScanResult

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    from rich.rule import Rule
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console(width=None) if HAS_RICH else None

RISK_COLORS = {
    "SAFE":    "bold green",
    "LOW":     "bold yellow",
    "MEDIUM":  "bold orange3",
    "HIGH":    "bold red",
    "UNKNOWN": "dim",
}

SEVERITY_ICONS = {
    "LOW":    "🟡",
    "MEDIUM": "🟠",
    "HIGH":   "🔴",
}


def print_banner():
    if not HAS_RICH:
        print("\n=== Web Cache Deception Detector ===\n")
        return
    console.print()
    console.print(Panel.fit(
        "[bold white]Web Cache Deception Detector[/bold white]\n"
        "[dim]Educational tool — passive header analysis only. No exploitation.[/dim]",
        border_style="dim white",
        padding=(0, 2),
    ))
    console.print()


def print_result(result: ScanResult):
    if not HAS_RICH:
        _plain_print(result)
        return

    if result.error:
        console.print(f"[red]✗ Error:[/red] {result.error}\n")
        return

    risk_color = RISK_COLORS.get(result.risk_level, "white")
    cf_badge = "[cyan]Cloudflare ✓[/cyan]" if result.is_cloudflare else "[dim]No Cloudflare[/dim]"
    server_str = f"[dim]Server: {result.server}[/dim]"

    console.print(Rule(f"[bold]{result.domain}[/bold]", style="dim white"))
    console.print(f"  {cf_badge}  {server_str}  [dim]Scan time: {result.scan_time}s[/dim]")
    console.print()

    # ── results table ─────────────────────────────────────────────────────────
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        padding=(0, 1),
        expand=True,        # use full terminal width
    )
    table.add_column("Check",    style="white",  min_width=24, no_wrap=True)
    table.add_column("Result",   min_width=12,   no_wrap=True)
    table.add_column("Severity", min_width=12,   no_wrap=True)
    table.add_column("Detail",   style="dim",    ratio=1)     # ratio=1 fills remaining space and wraps

    for c in result.checks:
        if c.passed:
            result_str = "[green]✓ SAFE[/green]"
            sev_str    = "[dim]—[/dim]"
        else:
            icon       = SEVERITY_ICONS.get(c.severity, "⚪")
            result_str = "[yellow]⚠ FLAGGED[/yellow]"
            sev_str    = f"{icon} {c.severity}"

        table.add_row(c.name, result_str, sev_str, c.detail)   # full detail, no truncation

    console.print(table)

    # ── risk score bar ────────────────────────────────────────────────────────
    score_bar = _score_bar(result.risk_score)
    console.print(
        f"  Risk Score  {score_bar}  "
        f"[{risk_color}]{result.risk_score}/100 — {result.risk_level}[/{risk_color}]"
    )
    console.print()

    # ── recommendations ───────────────────────────────────────────────────────
    recs = _recommendations(result)
    if recs:
        console.print(Panel(
            recs,
            title="[yellow]Recommendations[/yellow]",
            border_style="yellow",
            padding=(0, 2),
        ))
    console.print()

    # ── per-check evidence ────────────────────────────────────────────────────
    flagged = [c for c in result.checks if not c.passed]
    if flagged:
        console.print("[dim]Evidence for flagged checks:[/dim]")
        for c in flagged:
            if c.evidence:
                import json
                console.print(f"\n  [yellow]{c.name}[/yellow]")
                for k, v in c.evidence.items():
                    console.print(f"    [dim]{k}:[/dim] {v}")
        console.print()


def _score_bar(score: int, width: int = 20) -> str:
    filled = int((score / 100) * width)
    color  = "red" if score >= 50 else "yellow" if score >= 25 else "green"
    bar    = "█" * filled + "░" * (width - filled)
    return f"[{color}]{bar}[/{color}]"


def _recommendations(result: ScanResult) -> str:
    lines = []
    for c in result.checks:
        if c.passed:
            continue
        if c.name == "Path Confusion":
            lines.append("• Add Cache-Control: no-store to all dynamic/HTML routes")
            lines.append("• Enable Cloudflare Cache Deception Armor in Cache Rules")
            lines.append("• Configure CDN to bypass cache when Content-Type is text/html")
        if c.name == "Cache-Control Headers":
            lines.append("• Set Cache-Control: no-store, private on all authenticated endpoints")
        if c.name == "CF Caches Dynamic Paths":
            lines.append("• Add Cloudflare Cache Rule: bypass cache for URI paths containing /account, /profile, /user, /dashboard")
        if c.name == "Vary: Cookie Header":
            lines.append("• Add Vary: Cookie to cacheable responses that depend on session state")
        if c.name == "Cookie + Cache Conflict":
            lines.append("• Never cache responses that include Set-Cookie — add Cache-Control: no-store")
    return "\n".join(lines) if lines else ""


def _plain_print(result: ScanResult):
    print(f"\n{'='*60}")
    print(f"Domain    : {result.domain}")
    print(f"Cloudflare: {result.is_cloudflare}")
    print(f"Risk      : {result.risk_score}/100 — {result.risk_level}")
    print()
    for c in result.checks:
        status = "SAFE" if c.passed else f"FLAGGED [{c.severity}]"
        print(f"  [{status}] {c.name}")
        print(f"    {c.detail}")
    print()


def main():
    targets = sys.argv[1:]

    if not targets:
        if HAS_RICH:
            console.print("[red]Usage:[/red] python cli.py https://example.com")
            console.print("[dim]       python cli.py site1.com site2.com site3.com[/dim]")
        else:
            print("Usage: python cli.py https://example.com")
        sys.exit(1)

    print_banner()

    for i, target in enumerate(targets):
        if not target.startswith("http"):
            target = "https://" + target

        if HAS_RICH:
            result_holder = [None]

            def run():
                result_holder[0] = scan(
                    target,
                    progress_cb=lambda m: progress.update(task, description=f"[dim]{m}[/dim]")
                )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(f"Scanning {target}…", total=None)
                t = threading.Thread(target=run)
                t.start()
                t.join()

            result = result_holder[0]
        else:
            result = scan(target, progress_cb=print)

        print_result(result)

        if i < len(targets) - 1:
            time.sleep(1)


if __name__ == "__main__":
    main()