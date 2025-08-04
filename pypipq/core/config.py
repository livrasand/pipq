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
        # 1. Load from config file
        if config_path:
            self._load_file_config(config_path)
        else:
            # Try default locations
            self._load_default_configs()
        
        # 2. Override with environment variables
        self._load_env_config()
    
    def _load_default_configs(self) -> None:
        """Load configuration from default locations."""
        # User config: ~/.config/pipq/config.toml
        user_config = Path.home() / ".config" / "pipq" / "config.toml"
        if user_config.exists():
            self._load_file_config(user_config)
        
        # Project config: ./pypipq.toml
        project_config = Path.cwd() / "pypipq.toml"
        if project_config.exists():
            self._load_file_config(project_config)
    
    def _load_file_config(self, config_path: Path) -> None:
        """Load configuration from a TOML file."""
        try:
            with open(config_path, "rb") as f:
                file_config = tomllib.load(f)
                self.config.update(file_config)
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
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert string values to appropriate types
                if config_key in ["auto_continue_warnings", "colors", "verbose"]:
                    self.config[config_key] = value.lower() in ("true", "1", "yes", "on")
                elif config_key == "timeout":
                    try:
                        self.config[config_key] = int(value)
                    except ValueError:
                        pass
                elif config_key in ["disable_validators", "enable_validators"]:
                    self.config[config_key] = [v.strip() for v in value.split(",") if v.strip()]
                else:
                    self.config[config_key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        self.config[key] = value
    
    def is_validator_enabled(self, validator_name: str) -> bool:
        """
        Check if a validator is enabled based on configuration.
        
        Args:
            validator_name: Name of the validator to check
            
        Returns:
            True if validator should run, False otherwise
        """
        # If enable_validators is specified, only those validators run
        if self.config["enable_validators"]:
            return validator_name in self.config["enable_validators"]
        
        # Otherwise, run all validators except disabled ones
        return validator_name not in self.config["disable_validators"]
    
    def should_prompt(self) -> bool:
        """Check if we should prompt user for confirmation."""
        return self.config["mode"] in ["warn", "block"]
    
    def should_block(self) -> bool:
        """Check if we should block installation on errors."""
        return self.config["mode"] == "block"
    
    def should_auto_continue(self) -> bool:
        """Check if we should auto-continue on warnings."""
        return self.config["auto_continue_warnings"]
    
    def __str__(self) -> str:
        """String representation of the configuration."""
        return f"Config({self.config})"
