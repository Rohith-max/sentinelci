"""
Git hook management for pre-commit scanning
"""

import os
import shutil
from pathlib import Path
from sentinelci.scanner import run_scan


HOOK_SCRIPT = """#!/bin/bash
# SentinelCI Pre-commit Hook
# Automatically generated - do not edit manually

set -e

# Run sentinelci scan on staged changes
if ! sentinelci scan --diff --severity critical {blocking_flag} > /dev/null 2>&1; then
    if [ "{blocking}" = "true" ]; then
        echo "❌ Pre-commit hook failed: CRITICAL security issues found"
        exit 1
    else
        echo "⚠️  Pre-commit hook: Security issues detected (non-blocking)"
    fi
fi

exit 0
"""


def _get_hook_path() -> Path:
    """Get the path to the git pre-commit hook"""
    git_dir = Path(".git")
    if not git_dir.exists():
        raise RuntimeError("Not a git repository - run this command from repo root")

    return git_dir / "hooks" / "pre-commit"


def install_hook(blocking: bool = False) -> None:
    """
    Install pre-commit git hook

    Args:
        blocking: If True, commit fails on critical findings
    """
    hook_path = _get_hook_path()

    # Create hooks directory if needed
    hook_path.parent.mkdir(parents=True, exist_ok=True)

    # Backup existing hook
    if hook_path.exists():
        backup_path = hook_path.with_suffix(".bak")
        shutil.copy(hook_path, backup_path)
        print(f"✓ Backed up existing hook to {backup_path}")

    # Write new hook
    blocking_str = "true" if blocking else "false"
    blocking_flag = "--halt-on-critical" if blocking else ""

    hook_content = HOOK_SCRIPT.format(
        blocking=blocking_str,
        blocking_flag=blocking_flag,
    )

    hook_path.write_text(hook_content)
    hook_path.chmod(0o755)

    print(f"✓ Installed pre-commit hook to {hook_path}")
    print(f"✓ Blocking mode: {'enabled' if blocking else 'disabled'}")


def remove_hook() -> None:
    """
    Remove pre-commit git hook and restore backup if exists

    """
    hook_path = _get_hook_path()

    if not hook_path.exists():
        print("ℹ️  No SentinelCI hook installed")
        return

    # Check if it's our hook
    if "SentinelCI" not in hook_path.read_text():
        print("⚠️  Hook doesn't appear to be SentinelCI hook - skipping removal")
        return

    # Remove hook
    hook_path.unlink()
    print(f"✓ Removed hook from {hook_path}")

    # Restore backup if exists
    backup_path = hook_path.with_suffix(".bak")
    if backup_path.exists():
        shutil.copy(backup_path, hook_path)
        backup_path.unlink()
        print(f"✓ Restored original hook from backup")
