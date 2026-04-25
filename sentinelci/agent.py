"""
Claude-powered security analysis agent with tool-use
"""

import asyncio
import json
from typing import Optional
from anthropic import Anthropic


# Tool definitions for Claude
TOOLS = [
    {
        "name": "analyze_threat",
        "description": "Analyze a security threat and provide risk assessment and remediation advice",
        "input_schema": {
            "type": "object",
            "properties": {
                "threat_type": {
                    "type": "string",
                    "description": "Type of threat (secret, homograph, cve)",
                },
                "severity": {"type": "string", "description": "Severity level (CRITICAL, HIGH, MEDIUM, LOW)"},
                "details": {"type": "string", "description": "Details about the threat"},
                "location": {"type": "string", "description": "File or component location"},
            },
            "required": ["threat_type", "severity", "details", "location"],
        },
    },
    {
        "name": "suggest_remediation",
        "description": "Provide remediation steps for a security vulnerability",
        "input_schema": {
            "type": "object",
            "properties": {
                "threat_type": {
                    "type": "string",
                    "description": "Type of threat (secret, homograph, cve)",
                },
                "component": {
                    "type": "string",
                    "description": "Component or tool to remediate",
                },
                "details": {"type": "string", "description": "Threat details"},
            },
            "required": ["threat_type", "component", "details"],
        },
    },
]

# System prompt for security analysis
SYSTEM_PROMPT = """You are SentinelCI, an expert security analyst powered by Claude. Your role is to analyze security threats detected in code and provide clear, actionable remediation advice.

You have access to tools that allow you to:
1. Analyze threats and assess their risk
2. Suggest remediation steps

When given a list of security findings, you should:
1. Analyze each threat with context
2. Provide risk assessment based on type and location
3. Suggest practical remediation steps
4. Prioritize critical findings
5. Provide code examples when possible

Be concise but thorough. Focus on actionable advice that developers can immediately implement."""


def _handle_analyze_threat(threat_type: str, severity: str, details: str, location: str) -> str:
    """Tool handler for threat analysis"""
    analysis = f"""
**Threat Analysis: {threat_type.upper()}**
- Severity: {severity}
- Location: {location}

Risk Assessment:
The detected {threat_type} in {location} presents a {severity.lower()} risk to the system.
Details: {details}

Key Concerns:
1. Exposure of sensitive information
2. Potential for unauthorized access or exploitation
3. Compliance and regulatory implications

Recommended Actions:
- Review and rotate any exposed credentials
- Update vulnerable components
- Implement monitoring for similar vulnerabilities
"""
    return analysis.strip()


def _handle_suggest_remediation(threat_type: str, component: str, details: str) -> str:
    """Tool handler for remediation suggestions"""
    remediation_steps = {
        "secret": f"""
**Remediation Steps for {component}:**

1. Immediate Actions:
   - Revoke/rotate the exposed secret
   - Change passwords and API keys
   - Check logs for unauthorized access

2. Code Cleanup:
   - Remove the secret from code history (use git-filter-branch or BFG Repo-Cleaner)
   - Update your .gitignore to prevent future leaks
   - Use environment variables for sensitive values

3. Example Fix:
   # Before (WRONG):
   api_key = "sk-abc123def456"
   
   # After (CORRECT):
   import os
   api_key = os.getenv("API_KEY")

4. Prevention:
   - Use secrets management tools (AWS Secrets Manager, HashiCorp Vault)
   - Enable pre-commit hooks with trufflehog
   - Regular secret scanning in CI/CD pipeline
""",
        "homograph": f"""
**Remediation Steps for {component}:**

1. Verify Domain Legitimacy:
   - Check domain ownership and DNS records
   - Verify with legitimate service providers
   - Review recent changes to domain configuration

2. Code Changes:
   - Replace suspicious domain with verified legitimate domain
   - Use hardcoded whitelists for critical domains
   - Implement domain verification in configuration

3. Example Fix:
   # Before:
   api_url = "https://api-cdn.com"  # Unicode characters hidden
   
   # After:
   api_url = "https://api-cdn.com"  # Verified ASCII domain

4. Prevention:
   - Use code review to catch unusual Unicode
   - Implement domain pinning for critical services
   - Regular security audits of external URLs
""",
        "cve": f"""
**Remediation Steps for {component}:**

1. Assess Impact:
   - Determine if component is actually exploitable in your context
   - Check if vulnerable code path is used in your application

2. Update Component:
   - Upgrade to patched version if available
   - Test thoroughly in staging environment
   - Deploy updates following your release process

3. Temporary Mitigations (if update not available):
   - Disable vulnerable features if possible
   - Restrict access to vulnerable functionality
   - Monitor for exploitation attempts

4. Follow-up:
   - Subscribe to security advisories for {component}
   - Include dependency scanning in CI/CD
   - Regular vulnerability assessments
""",
    }

    threat_remediation = remediation_steps.get(threat_type, "Review security advisories and apply patches.")
    return f"**{component} - {threat_type.upper()} Remediation**" + threat_remediation


async def analyze_findings(findings: list, use_streaming: bool = False) -> str:
    """
    Use Claude with tool-use to analyze security findings

    Args:
        findings: List of security findings (dict format)
        use_streaming: Whether to stream responses

    Returns:
        Analysis summary from Claude
    """
    from sentinelci.config import get_config

    config = get_config()
    api_key = config.get_api_key()

    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not configured")

    client = Anthropic(api_key=api_key)

    # Format findings for Claude
    findings_text = json.dumps(findings, indent=2)
    user_message = f"""Please analyze these security findings and provide recommendations:

{findings_text}

For each finding, analyze the threat and suggest remediation steps."""

    messages = [{"role": "user", "content": user_message}]

    # Agentic loop
    while True:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        # Check if we need to handle tool use
        if response.stop_reason == "tool_use":
            # Process tool calls
            tool_results = []

            for content_block in response.content:
                if content_block.type == "tool_use":
                    tool_name = content_block.name
                    tool_input = content_block.input

                    # Execute tool
                    if tool_name == "analyze_threat":
                        result = _handle_analyze_threat(
                            threat_type=tool_input.get("threat_type"),
                            severity=tool_input.get("severity"),
                            details=tool_input.get("details"),
                            location=tool_input.get("location"),
                        )
                    elif tool_name == "suggest_remediation":
                        result = _handle_suggest_remediation(
                            threat_type=tool_input.get("threat_type"),
                            component=tool_input.get("component"),
                            details=tool_input.get("details"),
                        )
                    else:
                        result = f"Unknown tool: {tool_name}"

                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": content_block.id,
                            "content": result,
                        }
                    )

            # Add assistant response and tool results to messages
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        else:
            # End of conversation - extract final text response
            final_response = ""
            for content_block in response.content:
                if hasattr(content_block, "text"):
                    final_response += content_block.text

            return final_response


def get_threat_advice(threat_type: str, details: str) -> str:
    """
    Get quick advice for a specific threat without full agentic loop

    Args:
        threat_type: Type of threat
        details: Threat details

    Returns:
        Advice string
    """
    if threat_type == "secret":
        return _handle_suggest_remediation("secret", "exposed_secret", details)
    elif threat_type == "homograph":
        return _handle_suggest_remediation("homograph", "suspicious_url", details)
    elif threat_type == "cve":
        return _handle_suggest_remediation("cve", "vulnerable_component", details)
    else:
        return "Unknown threat type. Please review security best practices."
