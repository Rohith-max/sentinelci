"""
Unit tests for security tools
"""

import pytest
from sentinelci.tools.secret_scanner import _mask_value
from sentinelci.tools.url_forensics import _has_suspicious_unicode


class TestSecretScanner:
    """Tests for secret scanner"""

    def test_mask_value(self):
        """Test value masking"""
        # Short value
        assert _mask_value("abc") == "***"

        # Long value
        masked = _mask_value("sk-abc123def456")
        assert masked.startswith("sk-")
        assert masked.endswith("456")
        assert "*" in masked

    def test_mask_value_custom_length(self):
        """Test masking with custom character count"""
        masked = _mask_value("verylongsecretvalue", show_chars=2)
        assert masked.startswith("ve")
        assert masked.endswith("ue")


class TestUrlForensics:
    """Tests for URL forensics"""

    def test_suspicious_unicode_detection(self):
        """Test detection of confusable characters"""
        # English domain - no suspicion
        is_sus, chars, _ = _has_suspicious_unicode("example.com")
        assert not is_sus

        # Domain with confusable Cyrillic 'a'
        is_sus, chars, _ = _has_suspicious_unicode("exаmple.com")
        assert is_sus
        assert len(chars) > 0

    def test_unicode_breakdown(self):
        """Test Unicode character breakdown"""
        is_sus, chars, breakdown = _has_suspicious_unicode("tëst")
        assert is_sus
        assert "tëst" in breakdown or "ë" in breakdown
