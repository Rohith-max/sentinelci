"""
Report generation for SentinelCI findings
"""

import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


def generate_json_report(
    findings: List[Dict[str, Any]],
    output_file: Optional[str] = None,
) -> str:
    """
    Generate JSON report

    Args:
        findings: List of security findings
        output_file: Optional file to write to

    Returns:
        JSON report string
    """
    report = {
        "metadata": {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "scan_type": "sentinelci",
            "tool_version": "0.1.0",
        },
        "summary": {
            "total_findings": len(findings),
            "critical": len([f for f in findings if f.get("severity") == "CRITICAL"]),
            "high": len([f for f in findings if f.get("severity") == "HIGH"]),
            "medium": len([f for f in findings if f.get("severity") == "MEDIUM"]),
            "low": len([f for f in findings if f.get("severity") == "LOW"]),
        },
        "findings": findings,
    }

    json_str = json.dumps(report, indent=2)

    if output_file:
        Path(output_file).write_text(json_str)

    return json_str


def generate_markdown_report(
    findings: List[Dict[str, Any]],
    output_file: Optional[str] = None,
) -> str:
    """
    Generate Markdown report (GitHub-ready)

    Args:
        findings: List of security findings
        output_file: Optional file to write to

    Returns:
        Markdown report string
    """
    lines = [
        "# SentinelCI Security Scan Report",
        "",
        f"**Scan Date:** {datetime.utcnow().isoformat()}",
        "",
        "## Summary",
        "",
    ]

    # Add summary stats
    critical = len([f for f in findings if f.get("severity") == "CRITICAL"])
    high = len([f for f in findings if f.get("severity") == "HIGH"])
    medium = len([f for f in findings if f.get("severity") == "MEDIUM"])
    low = len([f for f in findings if f.get("severity") == "LOW"])
    total = len(findings)

    lines.extend([
        f"- **Total Findings:** {total}",
        f"- **Critical:** {critical} 🔴",
        f"- **High:** {high} 🟠",
        f"- **Medium:** {medium} 🔵",
        f"- **Low:** {low} ⚪",
        "",
    ])

    if not findings:
        lines.append("✅ No security threats detected!")
    else:
        lines.extend([
            "## Findings",
            "",
        ])

        # Group by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity_findings = [f for f in findings if f.get("severity") == severity]
            if severity_findings:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "⚪"}[
                    severity
                ]
                lines.append(f"### {icon} {severity}")
                lines.append("")

                for i, finding in enumerate(severity_findings, 1):
                    lines.append(f"#### {i}. {finding.get('type', 'Unknown')}")
                    lines.append("")
                    lines.append(f"**Location:** `{finding.get('file', 'unknown')}:{finding.get('line_number', 0)}`")
                    lines.append("")

                    if "description" in finding:
                        lines.append(f"**Description:** {finding['description']}")
                        lines.append("")

                    if "severity" in finding:
                        lines.append(f"**Severity:** {finding['severity']}")
                        lines.append("")

                    if "confidence" in finding:
                        confidence = finding["confidence"] * 100
                        lines.append(f"**Confidence:** {confidence:.0f}%")
                        lines.append("")

                    if "value_masked" in finding:
                        lines.append(f"**Value:** `{finding['value_masked']}`")
                        lines.append("")

                    if "cvss_score" in finding:
                        lines.append(f"**CVSS Score:** {finding['cvss_score']:.1f}")
                        lines.append("")

                    # Add remediation section
                    lines.append("**Remediation:**")
                    lines.append("")
                    if finding.get("type") == "Hardcoded Secret":
                        lines.extend([
                            "1. Revoke the exposed secret immediately",
                            "2. Remove from git history using `git filter-branch` or BFG Repo-Cleaner",
                            "3. Update `.gitignore` to prevent future leaks",
                            "4. Use environment variables for sensitive values",
                            "",
                        ])
                    elif finding.get("type") == "Homograph URL":
                        lines.extend([
                            "1. Verify the domain legitimacy",
                            "2. Replace with confirmed legitimate domain",
                            "3. Use hardcoded whitelists for critical domains",
                            "4. Implement domain pinning in configuration",
                            "",
                        ])
                    else:
                        lines.extend([
                            "1. Review the vulnerability details",
                            "2. Apply recommended patches or mitigations",
                            "3. Test changes in staging environment",
                            "",
                        ])

                lines.append("")

    markdown = "\n".join(lines)

    if output_file:
        Path(output_file).write_text(markdown)

    return markdown


def render_report(
    report_file: str,
    format: str = "terminal",
    output_file: Optional[str] = None,
) -> None:
    """
    Load and render a previously saved report

    Args:
        report_file: Path to JSON report file
        format: Output format (terminal, json, markdown, html)
        output_file: Optional file to write to
    """
    from sentinelci.output.terminal import render_findings, render_verdict

    # Load report
    report_path = Path(report_file)
    if not report_path.exists():
        raise FileNotFoundError(f"Report file not found: {report_file}")

    report_data = json.loads(report_path.read_text())
    findings = report_data.get("findings", [])
    summary = report_data.get("summary", {})

    if format == "terminal":
        render_findings(findings)
        render_verdict(
            critical_count=summary.get("critical", 0),
            high_count=summary.get("high", 0),
            halt_on_critical=False,
        )
    elif format == "json":
        json_report = json.dumps(report_data, indent=2)
        if output_file:
            Path(output_file).write_text(json_report)
        else:
            print(json_report)
    elif format == "markdown":
        md_report = generate_markdown_report(findings, output_file=output_file)
        if not output_file:
            print(md_report)
    elif format == "html":
        # Simple HTML conversion from markdown
        md_report = generate_markdown_report(findings)
        html = _markdown_to_html(md_report)
        if output_file:
            Path(output_file).write_text(html)
        else:
            print(html)


def _markdown_to_html(markdown: str) -> str:
    """Simple markdown to HTML converter"""
    try:
        import markdown
        return markdown.markdown(markdown)
    except ImportError:
        # Fallback to basic conversion
        html = "<html><body><pre>" + markdown + "</pre></body></html>"
        return html
