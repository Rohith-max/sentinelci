"""
Terminal output formatting using Rich library
"""

from typing import List, Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.style import Style


console = Console()

# Severity color mapping
SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "blue",
    "LOW": "dim",
}


def render_banner() -> None:
    """Render SentinelCI banner"""
    banner = """
    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██████╗ ██╗
    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║
    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ██║  ██║██║
    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██║  ██║██║
    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██████╔╝██║
    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═════╝ ╚═╝
    """
    console.print(banner, style="cyan bold")
    console.print(
        "🔍 AI-Powered Security Scanner", style="cyan bold", justify="center"
    )
    console.print()


def render_progress_scanners() -> None:
    """Show progress for parallel scanning"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task1 = progress.add_task("[cyan]Scanning for secrets...", total=None)
        task2 = progress.add_task("[cyan]Scanning for homographs...", total=None)
        task3 = progress.add_task("[cyan]Scanning for CVEs...", total=None)

        # Simulate scanning
        import time
        time.sleep(1)
        progress.update(task1, completed=True)
        time.sleep(1)
        progress.update(task2, completed=True)
        time.sleep(1)
        progress.update(task3, completed=True)


def render_finding(finding: Dict[str, Any]) -> Panel:
    """Render a single security finding as a Rich panel"""
    finding_type = finding.get("type", "Unknown")
    severity = finding.get("severity", "LOW")
    file_path = finding.get("file", "unknown")
    line_num = finding.get("line_number", 0)

    # Build content
    content_lines = []
    content_lines.append(f"[bold]Type:[/bold] {finding_type}")
    content_lines.append(f"[bold]Severity:[/bold] {severity}")
    content_lines.append(f"[bold]Location:[/bold] {file_path}:{line_num}")

    if "value_masked" in finding:
        content_lines.append(f"[bold]Value:[/bold] {finding['value_masked']}")

    if "description" in finding:
        content_lines.append(f"[bold]Description:[/bold] {finding['description']}")

    if "suspicious_chars" in finding:
        content_lines.append(
            f"[bold]Suspicious Characters:[/bold] {', '.join(finding['suspicious_chars'])}"
        )

    if "unicode_breakdown" in finding and finding["unicode_breakdown"]:
        content_lines.append(f"[bold]Unicode Details:[/bold]\n{finding['unicode_breakdown']}")

    if "cvss_score" in finding:
        content_lines.append(f"[bold]CVSS Score:[/bold] {finding['cvss_score']:.1f}")

    if "confidence" in finding:
        confidence_pct = finding["confidence"] * 100
        content_lines.append(f"[bold]Confidence:[/bold] {confidence_pct:.0f}%")

    content = "\n".join(content_lines)

    # Determine border color based on severity
    border_color = SEVERITY_COLORS.get(severity, "dim")

    return Panel(
        content,
        title=f"⚠️  {finding_type}",
        border_style=border_color,
        expand=False,
    )


def render_findings(findings: List[Dict[str, Any]]) -> None:
    """Render all findings with proper formatting"""
    render_banner()

    if not findings:
        console.print("[green]✅ No security threats detected![/green]")
        return

    console.print(f"[yellow]⚠️  Found {len(findings)} security issue(s)[/yellow]\n")

    # Group findings by severity
    by_severity = {}
    for finding in findings:
        severity = finding.get("severity", "LOW")
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)

    # Render by severity order
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity in by_severity:
            findings_for_severity = by_severity[severity]
            console.print(
                f"\n[bold {SEVERITY_COLORS[severity]}]{severity} ({len(findings_for_severity)})[/bold {SEVERITY_COLORS[severity]}]"
            )

            for finding in findings_for_severity:
                panel = render_finding(finding)
                console.print(panel)

    # Summary table
    console.print("\n[bold]Summary[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity in by_severity:
            count = len(by_severity[severity])
            table.add_row(severity, str(count), style=SEVERITY_COLORS[severity])

    console.print(table)


def render_verdict(critical_count: int, high_count: int, halt_on_critical: bool) -> None:
    """Render final verdict"""
    console.print()

    if critical_count > 0:
        if halt_on_critical:
            console.print(
                "[bold red]❌ CRITICAL issues found - scan FAILED[/bold red]"
            )
        else:
            console.print(
                "[bold yellow]⚠️  CRITICAL issues detected but not blocking[/bold yellow]"
            )
    elif high_count > 0:
        console.print("[bold yellow]⚠️  HIGH severity issues found - review recommended[/bold yellow]")
    else:
        console.print("[bold green]✅ Scan passed - no critical issues[/bold green]")


def render_analysis(analysis_text: str) -> None:
    """Render Claude AI analysis"""
    console.print("\n[bold cyan]📊 AI Analysis[/bold cyan]")
    console.print(Panel(analysis_text, border_style="cyan"))


def render_error(message: str) -> None:
    """Render error message"""
    console.print(f"[bold red]❌ Error: {message}[/bold red]")
