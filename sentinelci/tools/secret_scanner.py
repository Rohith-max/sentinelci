"""
Secret scanning tool using TruffleHog
"""

import json
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class SecretFinding:
    """Represents a secret finding"""

    type: str
    file: str
    line_number: int
    value_masked: str  # Masked sensitive value
    severity: str
    confidence: float
    description: str

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)


def _mask_value(value: str, show_chars: int = 4) -> str:
    """Mask sensitive value, showing only first and last few characters"""
    if len(value) <= show_chars * 2:
        return "*" * len(value)
    return value[:show_chars] + "*" * (len(value) - show_chars * 2) + value[-show_chars:]


def scan_secrets(path: str = ".") -> List[SecretFinding]:
    """
    Scan for hardcoded secrets using TruffleHog

    Args:
        path: Directory or file to scan

    Returns:
        List of secret findings
    """
    findings: List[SecretFinding] = []

    try:
        # Run TruffleHog
        result = subprocess.run(
            ["trufflehog", "filesystem", path, "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0 and result.returncode != 1:
            # 0 = no secrets, 1 = secrets found, other = error
            print(f"⚠️  TruffleHog error: {result.stderr}")
            return findings

        # Parse JSON output
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)

                    # Extract relevant fields
                    detector_name = data.get("DetectorName", "Unknown")
                    file_path = data.get("SourceMetadata", {}).get("Data", {}).get("File", "unknown")
                    line_num = (
                        data.get("SourceMetadata", {}).get("Data", {}).get("Line", 0)
                    )
                    raw_value = data.get("Raw", "")
                    verified = data.get("Verified", False)

                    # Determine severity
                    if verified:
                        severity = "CRITICAL"
                        confidence = 0.95
                    else:
                        severity = "HIGH"
                        confidence = 0.85

                    # Create finding
                    finding = SecretFinding(
                        type=detector_name,
                        file=file_path,
                        line_number=line_num,
                        value_masked=_mask_value(raw_value),
                        severity=severity,
                        confidence=confidence,
                        description=f"Detected {detector_name} secret",
                    )
                    findings.append(finding)

                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        print("⚠️  TruffleHog not installed. Install with: pip install trufflehog")
    except subprocess.TimeoutExpired:
        print("⚠️  TruffleHog scan timed out")
    except Exception as e:
        print(f"⚠️  Secret scanning error: {str(e)}")

    return findings
