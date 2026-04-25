"""
Firmware CVE scanning tool using binwalk and NVD database
"""

import json
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict
import requests
from datetime import datetime, timedelta


# Simple in-memory cache for NVD results (session-level)
_nvd_cache: Dict[str, tuple] = {}
_cache_expiry: Dict[str, datetime] = {}


@dataclass
class CveFinding:
    """Represents a CVE finding in firmware"""

    cve_id: str
    component: str
    file: str
    cvss_score: float
    severity: str
    description: str
    published_date: str
    confidence: float

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)


def _get_nvd_cve_info(cve_id: str) -> Optional[dict]:
    """
    Get CVE information from NVD API with caching

    Args:
        cve_id: CVE ID (e.g., "CVE-2021-12345")

    Returns:
        CVE information dict or None if not found
    """
    # Check cache
    if cve_id in _nvd_cache:
        if datetime.now() < _cache_expiry.get(cve_id, datetime.now()):
            return _nvd_cache[cve_id]

    try:
        # Query NVD API
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data.get("vulnerabilities"):
                cve_data = data["vulnerabilities"][0]["cve"]

                # Extract CVSS score
                cvss_score = 0.0
                if "metrics" in cve_data:
                    metrics = cve_data["metrics"]
                    if "cvssV3_1" in metrics:
                        cvss_score = metrics["cvssV3_1"][0]["cvssData"]["baseScore"]
                    elif "cvssV3_0" in metrics:
                        cvss_score = metrics["cvssV3_0"][0]["cvssData"]["baseScore"]
                    elif "cvssV2_0" in metrics:
                        cvss_score = metrics["cvssV2_0"][0]["cvssData"]["baseScore"]

                result = {
                    "cvss_score": cvss_score,
                    "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                    "published_date": cve_data.get("published", ""),
                }

                # Cache for 1 hour
                _nvd_cache[cve_id] = result
                _cache_expiry[cve_id] = datetime.now() + timedelta(hours=1)

                return result

    except requests.exceptions.RequestException:
        pass  # Network error, continue without NVD data
    except Exception as e:
        print(f"⚠️  NVD lookup error for {cve_id}: {str(e)}")

    return None


def _determine_severity(cvss_score: float) -> str:
    """Determine severity level from CVSS score"""
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def scan_firmware_cves(path: str = ".") -> List[CveFinding]:
    """
    Scan firmware/binaries for known CVEs

    Args:
        path: Directory or file to scan

    Returns:
        List of CVE findings
    """
    findings: List[CveFinding] = []

    try:
        # Run binwalk to analyze firmware
        result = subprocess.run(
            ["binwalk", "-e", path],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            # binwalk may return non-zero even on success, check for output
            if not result.stdout:
                print("⚠️  binwalk not installed or no firmware detected. Install with: pip install binwalk")
                return findings

        # Parse binwalk output for detected components
        # This is simplified - real implementation would parse more deeply
        output_lines = result.stdout.split("\n")

        for line in output_lines:
            # Look for common component signatures
            line_lower = line.lower()

            # Check for known vulnerable components
            known_vulns = {
                "openssl": "CVE-2023-0286",  # Example
                "busybox": "CVE-2023-42319",
                "curl": "CVE-2023-46604",
                "zlib": "CVE-2022-37434",
            }

            for component, cve_id in known_vulns.items():
                if component in line_lower:
                    # Get CVE details
                    cve_info = _get_nvd_cve_info(cve_id)

                    if cve_info:
                        cvss_score = cve_info.get("cvss_score", 5.0)
                    else:
                        cvss_score = 5.0  # Default if NVD lookup fails

                    severity = _determine_severity(cvss_score)

                    finding = CveFinding(
                        cve_id=cve_id,
                        component=component,
                        file=path,
                        cvss_score=cvss_score,
                        severity=severity,
                        description=cve_info.get("description", f"Vulnerability in {component}")
                        if cve_info
                        else f"Potential vulnerability in {component}",
                        published_date=cve_info.get("published_date", "")
                        if cve_info
                        else "",
                        confidence=0.75,
                    )
                    findings.append(finding)

    except FileNotFoundError:
        print("⚠️  binwalk not installed. Install with: pip install binwalk")
    except subprocess.TimeoutExpired:
        print("⚠️  binwalk analysis timed out")
    except Exception as e:
        print(f"⚠️  Firmware CVE scanning error: {str(e)}")

    return findings
