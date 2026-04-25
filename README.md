# SentinelCI - Security Scanning CLI

A Python CLI tool that scans for security threats using AI-powered analysis with Claude.

## Features

- **Secret Scanning**: Detect hardcoded secrets using TruffleHog
- **Homograph Detection**: Identify visual URL spoofing attempts
- **CVE Analysis**: Scan firmware for known vulnerabilities
- **AI Enrichment**: Claude-powered threat analysis and remediation advice
- **Multiple Output Formats**: Terminal (Rich), JSON, and Markdown reports
- **Git Integration**: Pre-commit and post-commit hook support

## Installation

```bash
pip install sentinelci
```

## Quick Start

```bash
# Scan current git diff for threats
sentinelci scan

# Scan a specific directory
sentinelci scan --target /path/to/code

# Install git pre-commit hook
sentinelci hook install

# Generate a report from findings
sentinelci report findings.json
```

## Commands

- `sentinelci scan` - Scan for security threats
- `sentinelci watch` - Monitor commits for threats
- `sentinelci hook install/remove` - Manage git hooks
- `sentinelci report` - Generate or convert reports
- `sentinelci config` - Configure settings
- `sentinelci version` - Display version info

## Configuration

Configure via `~/.config/sentinelci/config.toml`:

```toml
[api]
anthropic_api_key = "sk-..."

[scan]
severity_threshold = "medium"
enable_firmware_scanning = true
enable_url_detection = true

[output]
format = "terminal"
```

## Documentation

For detailed usage and examples, see the included documentation.

## License

MIT
