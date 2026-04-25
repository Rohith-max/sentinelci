"""
URL forensics tool for detecting homograph attacks (visual spoofing)
"""

import re
import socket
from dataclasses import dataclass, asdict
from typing import List, Optional, Set
from unicodedata import normalize, category


@dataclass
class UrlFinding:
    """Represents a suspicious URL finding"""

    url: str
    file: str
    line_number: int
    type: str
    suspicious_chars: List[str]
    unicode_breakdown: str
    severity: str
    confidence: float
    description: str

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)


# Common confusable characters that can be used in homograph attacks
CONFUSABLES = {
    "а": "a",  # Cyrillic a
    "е": "e",  # Cyrillic e
    "о": "o",  # Cyrillic o
    "р": "r",  # Cyrillic r
    "с": "c",  # Cyrillic s
    "у": "u",  # Cyrillic u
    "х": "x",  # Cyrillic x
    "у": "y",  # Cyrillic y
    "ё": "e",  # Cyrillic yo
    "ы": "bl",  # Cyrillic bl
    "ē": "e",  # Macron e
    "ī": "i",  # Macron i
    "ō": "o",  # Macron o
    "ū": "u",  # Macron u
    "ā": "a",  # Macron a
    "è": "e",  # Grave e
    "í": "i",  # Acute i
    "ó": "o",  # Acute o
    "ú": "u",  # Acute u
}

# URL pattern
URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+"
    r"|[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}",
    re.UNICODE,
)


def _has_suspicious_unicode(domain: str) -> tuple[bool, List[str], str]:
    """
    Check if domain contains suspicious Unicode characters

    Returns:
        (is_suspicious, list_of_chars, unicode_breakdown)
    """
    suspicious_chars = []
    unicode_breakdown_parts = []

    for char in domain:
        if ord(char) > 127:  # Non-ASCII
            suspicious_chars.append(char)
            if char in CONFUSABLES:
                unicode_breakdown_parts.append(
                    f"{char} (U+{ord(char):04X}) - Confusable with '{CONFUSABLES[char]}'"
                )
            else:
                cat = category(char)
                unicode_breakdown_parts.append(f"{char} (U+{ord(char):04X}) - Category: {cat}")

    is_suspicious = len(suspicious_chars) > 0
    breakdown = "\n".join(unicode_breakdown_parts) if unicode_breakdown_parts else ""

    return is_suspicious, suspicious_chars, breakdown


def _try_resolve_dns(domain: str) -> bool:
    """Try to resolve domain via DNS"""
    try:
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.timeout):
        return False


def detect_homographs(path: str = ".") -> List[UrlFinding]:
    """
    Detect homograph URLs (visual spoofing attacks)

    Args:
        path: Directory to scan for URLs

    Returns:
        List of suspicious URL findings
    """
    findings: List[UrlFinding] = []

    try:
        import os
        from pathlib import Path

        # Walk through files
        for root, dirs, files in os.walk(path):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv"}]

            for file in files:
                # Skip binary files
                if file.endswith((".png", ".jpg", ".gif", ".bin", ".pyc")):
                    continue

                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            # Find URLs in line
                            for match in URL_PATTERN.finditer(line):
                                url = match.group()

                                # Extract domain
                                domain = url.replace("https://", "").replace("http://", "").split("/")[0]

                                # Check for suspicious Unicode
                                is_suspicious, suspicious_chars, breakdown = _has_suspicious_unicode(
                                    domain
                                )

                                if is_suspicious:
                                    # Try to resolve DNS
                                    resolves = _try_resolve_dns(domain)

                                    # Determine severity based on resolution
                                    if resolves:
                                        severity = "CRITICAL"
                                        confidence = 0.9
                                        desc = (
                                            f"Homograph domain resolves to IP - likely spoofing attack. "
                                            f"Domain uses confusable Unicode chars: {', '.join(suspicious_chars)}"
                                        )
                                    else:
                                        severity = "HIGH"
                                        confidence = 0.8
                                        desc = (
                                            f"Suspicious Unicode in domain (may not resolve). "
                                            f"Confusable chars: {', '.join(suspicious_chars)}"
                                        )

                                    finding = UrlFinding(
                                        url=url,
                                        file=filepath.replace(path, "").lstrip("/"),
                                        line_number=line_num,
                                        type="Homograph URL",
                                        suspicious_chars=suspicious_chars,
                                        unicode_breakdown=breakdown,
                                        severity=severity,
                                        confidence=confidence,
                                        description=desc,
                                    )
                                    findings.append(finding)

                except (IOError, UnicodeDecodeError):
                    continue

    except Exception as e:
        print(f"⚠️  URL detection error: {str(e)}")

    return findings
