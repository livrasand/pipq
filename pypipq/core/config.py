"""
Configuration management for pypipq.

Handles reading configuration from files and environment variables.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Fallback for older Python versions


class Config:
    """
    Configuration manager for pypipq.
    
    Loads configuration from:
    1. Environment variables (PIPQ_*)
    2. User config file (~/.config/pipq/config.toml)
    3. Project config file (./pypipq.toml)
    4. Default values
    """
    
    DEFAULT_CONFIG = {
        "mode": "warn",  # silent, warn, block
        "auto_continue_warnings": True,
        "disable_validators": [],
        "enable_validators": [],  # If specified, only these validators run
        "timeout": 30,  # Timeout for network requests
        "pypi_url": "https://pypi.org/pypi/",
        "colors": True,
        "verbose": False,
        "vulnerability": {
            "enabled": True,
            "update_interval_days": 7,
            "sources": ["osv", "safetydb", "pypa"],
        },
    }
    
    def __init__(self, config_path: Optional[Path] = None) -> None:
        """
        Initialize configuration manager.
        
        Args:
            config_path: Optional path to config file
        """
        self.config = self.DEFAULT_CONFIG.copy()
        self._load_config(config_path)
    
    def _load_config(self, config_path: Optional[Path] = None) -> None:
        """Load configuration from various sources."""
        if config_path:
            self._load_file_config(config_path)
        else:
            self._load_default_configs()
        
        self._load_env_config()
    
    def _load_default_configs(self) -> None:
        """Load configuration from default locations."""
        user_config = Path.home() / ".config" / "pipq" / "config.toml"
        if user_config.exists():
            self._load_file_config(user_config)
        
        project_config = Path.cwd() / "pypipq.toml"
        if project_config.exists():
            self._load_file_config(project_config)
    
    def _merge_configs(self, base: Dict[str, Any], new: Dict[str, Any]) -> None:
        """Recursively merge new config into base config."""
        for key, value in new.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                self._merge_configs(base[key], value)
            else:
                base[key] = value

    def _load_file_config(self, config_path: Path) -> None:
        """Load configuration from a TOML file."""
        try:
            with open(config_path, "rb") as f:
                file_config = tomllib.load(f)
                self._merge_configs(self.config, file_config)
        except Exception as e:
            print(f"Warning: Could not load config from {config_path}: {e}")
    
    def _load_env_config(self) -> None:
        """Load configuration from environment variables."""
        env_mapping = {
            "PIPQ_MODE": "mode",
            "PIPQ_AUTO_CONTINUE": "auto_continue_warnings",
            "PIPQ_DISABLE_VALIDATORS": "disable_validators",
            "PIPQ_ENABLE_VALIDATORS": "enable_validators",
            "PIPQ_TIMEOUT": "timeout",
            "PIPQ_PYPI_URL": "pypi_url",
            "PIPQ_COLORS": "colors",
            "PIPQ_VERBOSE": "verbose",
            "PIPQ_VULNERABILITY_ENABLED": "vulnerability.enabled",
            "PIPQ_VULNERABILITY_CACHE_DIR": "vulnerability.cache_dir",
            "PIPQ_VULNERABILITY_UPDATE_INTERVAL_DAYS": "vulnerability.update_interval_days",
            "PIPQ_VULNERABILITY_SOURCES": "vulnerability.sources",
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                keys = config_key.split('.')
                target_config = self.config
                for key in keys[:-1]:
                    if key not in target_config or not isinstance(target_config[key], dict):
                        target_config[key] = {}
                    target_config = target_config[key]
                
                leaf_key = keys[-1]

                if leaf_key in ["auto_continue_warnings", "colors", "verbose", "enabled"]:
                    target_config[leaf_key] = value.lower() in ("true", "1", "yes", "on")
                elif leaf_key in ["timeout", "update_interval_days"]:
                    try:
                        target_config[leaf_key] = int(value)
                    except ValueError:
                        pass
                elif leaf_key in ["disable_validators", "enable_validators", "sources"]:
                    target_config[leaf_key] = [v.strip() for v in value.split(",") if v.strip()]
                else:
                    target_config[leaf_key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        keys = key.split('.')
        value = self.config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        keys = key.split('.')
        target_config = self.config
        for k in keys[:-1]:
            target_config = target_config.setdefault(k, {})
        target_config[keys[-1]] = value

    def is_validator_enabled(self, validator_name: str) -> bool:
        """
        Check if a validator is enabled based on configuration.
        
        Args:
            validator_name: Name of the validator to check
            
        Returns:
            True if validator should run, False otherwise
        """
        validator_config = self.get(f"{validator_name.lower()}")
        if isinstance(validator_config, dict) and "enabled" in validator_config:
            if not validator_config["enabled"]:
                return False

        if self.get("enable_validators"):
            return validator_name in self.get("enable_validators")
        
        return validator_name not in self.get("disable_validators")
    
    def should_prompt(self) -> bool:
        """Check if we should prompt user for confirmation."""
        return self.get("mode") in ["warn", "block"]
    
    def should_block(self) -> bool:
        """Check if we should block installation on errors."""
        return self.get("mode") == "block"
    
    def should_auto_continue(self) -> bool:
        """Check if we should auto-continue on warnings."""
        return self.get("auto_continue_warnings")
    
    def __str__(self) -> str:
        """String representation of the configuration."""
        return f"Config({self.config})"