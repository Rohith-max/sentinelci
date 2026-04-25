"""
Configuration management for SentinelCI
"""

import os
import sys
from pathlib import Path
from typing import Optional
import tomli_w

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import platformdirs


class Config:
    """Manages SentinelCI configuration files"""

    def __init__(self):
        """Initialize config from file or environment"""
        self.config_dir = Path(platformdirs.user_config_dir("sentinelci", "sentinelci"))
        self.config_file = self.config_dir / "config.toml"
        self._config = self._load_config()

    def _load_config(self) -> dict:
        """Load configuration from file, creating defaults if needed"""
        if self.config_file.exists():
            with open(self.config_file, "rb") as f:
                return tomllib.load(f)
        return self._default_config()

    def _default_config(self) -> dict:
        """Return default configuration"""
        return {
            "api": {
                "anthropic_api_key": None,
            },
            "scan": {
                "severity_threshold": "medium",
                "enable_firmware_scanning": True,
                "enable_url_detection": True,
            },
            "output": {
                "format": "terminal",
            },
        }

    def get(self, section: str, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a configuration value"""
        if section not in self._config:
            return default
        return self._config[section].get(key, default)

    def set(self, section: str, key: str, value: str) -> None:
        """Set a configuration value and save to file"""
        if section not in self._config:
            self._config[section] = {}
        self._config[section][key] = value
        self.save()

    def save(self) -> None:
        """Save configuration to file"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, "wb") as f:
            tomli_w.dump(self._config, f)

    def get_api_key(self) -> Optional[str]:
        """Get Anthropic API key from config or environment"""
        # Check environment variable first
        if api_key := os.environ.get("ANTHROPIC_API_KEY"):
            return api_key

        # Check config file
        api_key = self.get("api", "anthropic_api_key")
        if api_key:
            return api_key

        return None

    def setup_wizard(self) -> None:
        """Interactive setup wizard for initial configuration"""
        print("\n🔧 SentinelCI Configuration Wizard\n")

        # API Key setup
        current_key = self.get_api_key()
        if current_key:
            prompt = f"Anthropic API Key (current: {current_key[:10]}...): "
        else:
            prompt = "Anthropic API Key (required): "

        api_key = input(prompt).strip()
        if api_key:
            self.set("api", "anthropic_api_key", api_key)
            print("✓ API key saved")

        # Severity threshold
        severity = input("Minimum severity (low/medium/high/critical) [medium]: ").strip()
        if severity and severity in ["low", "medium", "high", "critical"]:
            self.set("scan", "severity_threshold", severity)
            print(f"✓ Severity threshold set to {severity}")

        # Firmware scanning
        firmware = input("Enable firmware CVE scanning (y/n) [y]: ").strip().lower()
        if firmware == "n":
            self.set("scan", "enable_firmware_scanning", "false")
            print("✓ Firmware scanning disabled")

        # URL detection
        urls = input("Enable homograph URL detection (y/n) [y]: ").strip().lower()
        if urls == "n":
            self.set("scan", "enable_url_detection", "false")
            print("✓ URL detection disabled")

        print(f"\n✅ Configuration saved to {self.config_file}\n")

    def validate(self) -> bool:
        """Validate that required configuration is present"""
        if not self.get_api_key():
            print("❌ Error: ANTHROPIC_API_KEY not configured")
            print("\nRun 'sentinelci config' to set up your API key")
            print("Or set the ANTHROPIC_API_KEY environment variable")
            return False
        return True


def get_config() -> Config:
    """Get or create the global configuration"""
    return Config()
