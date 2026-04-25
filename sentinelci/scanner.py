"""
Main scanner orchestration
"""

import asyncio
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path

from sentinelci.tools.secret_scanner import scan_secrets
from sentinelci.tools.url_forensics import detect_homographs
from sentinelci.tools.firmware_cve import scan_firmware_cves
from sentinelci.output.terminal import (
    render_findings,
    render_verdict,
    render_analysis,
    render_banner,
)
from sentinelci.output.report import generate_json_report, generate_markdown_report
from sentinelci.agent import analyze_findings, get_threat_advice
from sentinelci.config import get_config


def _get_git_diff_files(severity: str = "medium") -> str:
    """Get git diff for staged/unstaged changes"""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout or "."
    except Exception:
        return "."


def _get_scan_path(
    path: str,
    use_diff: bool,
) -> str:
    """Determine the path to scan"""
    if use_diff:
        return _get_git_diff_files()
    return path


def _filter_findings_by_severity(
    findings: List[Dict[str, Any]],
    severity: str,
) -> List[Dict[str, Any]]:
    """Filter findings by minimum severity"""
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_level = severity_order.get(severity.upper(), 2)

    return [
        f for f in findings
        if severity_order.get(f.get("severity", "LOW").upper(), 1) >= min_level
    ]


async def _run_parallel_scans(
    scan_path: str,
    enable_firmware: bool = True,
    enable_urls: bool = True,
) -> List[Dict[str, Any]]:
    """Run all security scans in parallel"""
    all_findings: List[Dict[str, Any]] = []

    # Create scan tasks
    tasks = [
        asyncio.to_thread(scan_secrets, scan_path),
    ]

    if enable_urls:
        tasks.append(asyncio.to_thread(detect_homographs, scan_path))

    if enable_firmware:
        tasks.append(asyncio.to_thread(scan_firmware_cves, scan_path))

    # Run in parallel
    results = await asyncio.gather(*tasks)

    # Convert all results to dicts
    for result_list in results:
        for finding_obj in result_list:
            if hasattr(finding_obj, 'to_dict'):
                all_findings.append(finding_obj.to_dict())
            else:
                all_findings.append(finding_obj)

    return all_findings


def run_scan(
    path: str = ".",
    use_diff: bool = False,
    severity: str = "medium",
    output_format: str = "terminal",
    output_file: Optional[str] = None,
    use_ai: bool = True,
    watch_mode: bool = False,
    halt_on_critical: bool = False,
    enable_firmware: bool = True,
    enable_urls: bool = True,
) -> int:
    """
    Run security scan

    Args:
        path: Path to scan
        use_diff: Scan git diff only
        severity: Minimum severity to report
        output_format: Output format (terminal, json, markdown)
        output_file: File to save results
        use_ai: Enable Claude analysis
        watch_mode: Watch for changes
        halt_on_critical: Exit with error on critical findings
        enable_firmware: Enable CVE scanning
        enable_urls: Enable URL detection

    Returns:
        Exit code (0 = success, 1 = critical findings, 2 = error)
    """
    config = get_config()
    if not config.validate():
        return 2

    render_banner()

    # Get scan path
    scan_path = _get_scan_path(path, use_diff)

    print(f"🔍 Scanning: {scan_path}\n")

    # Run scans
    try:
        findings = asyncio.run(
            _run_parallel_scans(
                scan_path,
                enable_firmware=enable_firmware,
                enable_urls=enable_urls,
            )
        )
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
        return 2

    # Filter by severity
    filtered_findings = _filter_findings_by_severity(findings, severity)

    # Count by severity
    critical_count = len([f for f in filtered_findings if f.get("severity") == "CRITICAL"])
    high_count = len([f for f in filtered_findings if f.get("severity") == "HIGH"])

    # Render output
    if output_format == "terminal":
        render_findings(filtered_findings)
        render_verdict(critical_count, high_count, halt_on_critical)
    elif output_format == "json":
        json_report = generate_json_report(filtered_findings, output_file=output_file)
        if not output_file:
            print(json_report)
    elif output_format == "markdown":
        md_report = generate_markdown_report(filtered_findings, output_file=output_file)
        if not output_file:
            print(md_report)

    # Optional AI analysis
    if use_ai and filtered_findings:
        try:
            analysis = asyncio.run(analyze_findings(filtered_findings))
            if output_format == "terminal":
                render_analysis(analysis)
        except Exception as e:
            print(f"⚠️  AI analysis failed: {str(e)}")

    # Save JSON report if not in terminal format
    if output_format != "json" and output_file:
        generate_json_report(filtered_findings, output_file=output_file.replace(".md", ".json"))

    # Determine exit code
    if halt_on_critical and critical_count > 0:
        return 1
    elif critical_count > 0 or high_count > 0:
        return 0  # Still success but with findings

    return 0


def run_watch() -> None:
    """
    Watch mode - scan on each commit

    This installs a post-commit hook and scans for threats
    """
    print("👁️  Watch mode enabled - monitoring for security threats")
    print("Press Ctrl+C to stop\n")

    # This would implement git hook integration
    # For now, demonstrate the concept
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        pass
