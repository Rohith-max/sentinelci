"""
Command-line interface for SentinelCI
"""

import sys
import click
from sentinelci import __version__
from sentinelci.config import get_config


@click.group()
@click.version_option(version=__version__, prog_name="sentinelci")
def main() -> None:
    """SentinelCI - AI-powered security scanning for your code"""
    pass


@main.command()
@click.argument("path", default=".", required=False)
@click.option("--diff", is_flag=True, help="Scan git diff instead of directory")
@click.option("--target", type=click.Path(), help="Target directory or file to scan")
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Minimum severity level to report",
)
@click.option(
    "--format",
    type=click.Choice(["terminal", "json", "markdown"]),
    default="terminal",
    help="Output format",
)
@click.option(
    "--output", type=click.Path(), help="Output file path (for json/markdown formats)"
)
@click.option("--no-ai", is_flag=True, help="Disable Claude AI analysis")
@click.option("--watch", is_flag=True, help="Watch mode - scan on each commit")
@click.option("--halt-on-critical", is_flag=True, help="Exit with error on critical findings")
@click.option("--no-firmware", is_flag=True, help="Disable firmware CVE scanning")
@click.option("--no-urls", is_flag=True, help="Disable homograph URL detection")
def scan(
    path: str,
    diff: bool,
    target: str,
    severity: str,
    format: str,
    output: str,
    no_ai: bool,
    watch: bool,
    halt_on_critical: bool,
    no_firmware: bool,
    no_urls: bool,
) -> None:
    """Scan for security threats"""
    from sentinelci.scanner import run_scan

    config = get_config()
    if not config.validate():
        sys.exit(1)

    try:
        exit_code = run_scan(
            path=target or path,
            use_diff=diff,
            severity=severity,
            output_format=format,
            output_file=output,
            use_ai=not no_ai,
            watch_mode=watch,
            halt_on_critical=halt_on_critical,
            enable_firmware=not no_firmware,
            enable_urls=not no_urls,
        )
        sys.exit(exit_code)
    except Exception as e:
        click.echo(f"❌ Scan failed: {str(e)}", err=True)
        sys.exit(1)


@main.command()
def watch() -> None:
    """Watch for threats on each commit"""
    from sentinelci.scanner import run_watch

    config = get_config()
    if not config.validate():
        sys.exit(1)

    try:
        run_watch()
    except KeyboardInterrupt:
        click.echo("\n⏹️  Watch mode stopped")
        sys.exit(0)
    except Exception as e:
        click.echo(f"❌ Watch failed: {str(e)}", err=True)
        sys.exit(1)


@main.group()
def hook() -> None:
    """Manage git hooks for pre-commit scanning"""
    pass


@hook.command()
@click.option(
    "--blocking",
    is_flag=True,
    help="Fail commit on critical findings (default: warn only)",
)
def install(blocking: bool) -> None:
    """Install pre-commit git hook"""
    from sentinelci.hooks import install_hook

    try:
        install_hook(blocking=blocking)
        click.echo("✅ Git hook installed successfully")
    except Exception as e:
        click.echo(f"❌ Failed to install hook: {str(e)}", err=True)
        sys.exit(1)


@hook.command()
def remove() -> None:
    """Remove git hook"""
    from sentinelci.hooks import remove_hook

    try:
        remove_hook()
        click.echo("✅ Git hook removed")
    except Exception as e:
        click.echo(f"❌ Failed to remove hook: {str(e)}", err=True)
        sys.exit(1)


@main.command()
@click.argument("incident_file", required=False)
@click.option(
    "--format",
    type=click.Choice(["terminal", "json", "markdown", "html"]),
    default="terminal",
    help="Output format for the report",
)
@click.option("--output", type=click.Path(), help="Save report to file")
def report(incident_file: str, format: str, output: str) -> None:
    """Generate or convert security reports"""
    from sentinelci.output.report import render_report

    try:
        render_report(incident_file or "findings.json", format=format, output_file=output)
    except Exception as e:
        click.echo(f"❌ Report generation failed: {str(e)}", err=True)
        sys.exit(1)


@main.command()
def config() -> None:
    """Configure SentinelCI settings"""
    cfg = get_config()
    cfg.setup_wizard()


@main.command()
def version() -> None:
    """Display version and environment information"""
    import platform
    from anthropic import __version__ as anthropic_version

    click.echo(f"SentinelCI {__version__}")
    click.echo(f"Python {platform.python_version()}")
    click.echo(f"Anthropic SDK {anthropic_version}")
    click.echo(f"Claude Model: claude-sonnet-4-20250514")


if __name__ == "__main__":
    main()
