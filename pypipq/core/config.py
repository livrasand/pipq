"""Manages configuration for pypipq.

This module is responsible for loading, managing, and saving the application's
configuration settings. It aggregates settings from default values, TOML files,
and environment variables, providing a unified interface for accessing them.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import tomllib  # Available in Python 3.11+
except ImportError:
    import tomli as tomllib  # Fallback for Python versions < 3.11

# The default path for the user-specific global configuration file.
USER_CONFIG_PATH = Path.home() / ".config" / "pipq" / "config.toml"


class Config:
    """Handles the configuration for the pypipq application.

    This class loads configuration from multiple sources with a defined
    precedence:
    1.  Default values (lowest precedence).
    2.  Project-specific `pipq-workspace.toml` file.
    3.  User-level `~/.config/pipq/config.toml` file.
    4.  A custom configuration file specified at runtime.
    5.  Environment variables (highest precedence).

    Attributes:
        DEFAULT_CONFIG (Dict[str, Any]): A dictionary containing the default
            configuration values.
    """

    DEFAULT_CONFIG = {
        "mode": "interactive",  # Can be "interactive", "silent", or "block".
        "auto_continue_warnings": True,
        "disable_validators": [],
        "enable_validators": [],  # If specified, only these validators run.
        "timeout": 30,  # Network request timeout in seconds.
        "pypi_url": "https://pypi.org/pypi/",
        "colors": True,
        "verbose": False,
        "vulnerability": {
            "enabled": True,
            "update_interval_days": 7,
            "sources": ["osv", "safetydb", "pypa"],
        },
        "security": {
            "minimum_release_age": 0,  # Disabled by default.
            "minimum_release_age_exclude": [],
            "package_policies": {}
        }
    }

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """Initializes the configuration manager.

        Args:
            config_path (Optional[Path]): An optional path to a specific
                configuration file to load. If provided, it takes precedence
                over default file locations.
        """
        self.config = self.DEFAULT_CONFIG.copy()
        self._load_config(config_path)

    def _load_config(self, config_path: Optional[Path] = None) -> None:
        """Loads configuration from files and environment variables.

        Args:
            config_path (Optional[Path]): A specific config file path.
        """
        if config_path:
            self._load_file_config(config_path)
        else:
            self._load_default_configs()

        self._load_env_config()

    def _load_default_configs(self) -> None:
        """Loads configs from standard locations if they exist."""
        project_config = Path.cwd() / "pipq-workspace.toml"
        if project_config.exists():
            self._load_file_config(project_config)

        if USER_CONFIG_PATH.exists():
            self._load_file_config(USER_CONFIG_PATH)

    def _merge_configs(self, base: Dict[str, Any], new: Dict[str, Any]) -> None:
        """Recursively merges a new config dict into a base dict.

        Args:
            base (Dict[str, Any]): The base configuration dictionary.
            new (Dict[str, Any]): The new configuration to merge in.
        """
        for key, value in new.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                self._merge_configs(base[key], value)
            else:
                base[key] = value

    def _load_file_config(self, config_path: Path) -> None:
        """Loads and merges configuration from a TOML file.

        Args:
            config_path (Path): The path to the TOML configuration file.
        """
        try:
            with open(config_path, "rb") as f:
                file_config = tomllib.load(f)
                self._merge_configs(self.config, file_config)
        except Exception as e:
            print(f"Warning: Could not load config from {config_path}: {e}", file=sys.stderr)

    def _load_env_config(self) -> None:
        """Loads and merges configuration from environment variables."""
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
            "PIPQ_MINIMUM_RELEASE_AGE": "security.minimum_release_age",
            "PIPQ_MINIMUM_RELEASE_AGE_EXCLUDE": "security.minimum_release_age_exclude",
        }

        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                self._set_nested_key(config_key, value)

    def _set_nested_key(self, key_path: str, value: str) -> None:
        """Sets a value in the config dict using a dot-separated path.

        This method correctly parses and casts values from environment
        variables, which are always strings.

        Args:
            key_path (str): The dot-separated key (e.g., "vulnerability.enabled").
            value (str): The string value from the environment variable.
        """
        keys = key_path.split('.')
        target_config = self.config
        for key in keys[:-1]:
            if key not in target_config or not isinstance(target_config[key], dict):
                target_config[key] = {}
            target_config = target_config[key]

        leaf_key = keys[-1]

        # Type casting based on the key
        if leaf_key in ["auto_continue_warnings", "colors", "verbose", "enabled"]:
            target_config[leaf_key] = value.lower() in ("true", "1", "yes", "on")
        elif leaf_key in ["timeout", "update_interval_days", "minimum_release_age"]:
            try:
                target_config[leaf_key] = int(value)
            except ValueError:
                print(f"Warning: Invalid integer value for {leaf_key}: {value}", file=sys.stderr)
        elif leaf_key in ["disable_validators", "enable_validators", "sources", "minimum_release_age_exclude"]:
            target_config[leaf_key] = [v.strip() for v in value.split(",") if v.strip()]
        else:
            target_config[leaf_key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a configuration value using a dot-separated key.

        Args:
            key (str): The dot-separated key (e.g., "vulnerability.enabled").
            default (Any): The default value to return if the key is not found.

        Returns:
            Any: The configuration value or the default.
        """
        keys = key.split('.')
        value = self.config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """Sets a configuration value in memory.

        Args:
            key (str): The dot-separated key (e.g., "vulnerability.enabled").
            value (Any): The value to set.
        """
        keys = key.split('.')
        target_config = self.config
        for k in keys[:-1]:
            target_config = target_config.setdefault(k, {})
        target_config[keys[-1]] = value

    def is_validator_enabled(self, validator_name: str) -> bool:
        """Checks if a specific validator is enabled.

        The logic is as follows:
        - If the validator has an `enabled: false` setting, it's disabled.
        - If `enable_validators` is set, the validator is enabled only if
          it's in that list.
        - Otherwise, the validator is enabled unless it's in the
          `disable_validators` list.

        Args:
            validator_name (str): The name of the validator to check.

        Returns:
            bool: True if the validator is enabled, False otherwise.
        """
        validator_config = self.get(f"{validator_name.lower()}")
        if isinstance(validator_config, dict) and validator_config.get("enabled") is False:
            return False

        enabled_list = self.get("enable_validators", [])
        if enabled_list:
            return validator_name in enabled_list

        disabled_list = self.get("disable_validators", [])
        return validator_name not in disabled_list

    def should_prompt(self) -> bool:
        """Determines if the application should prompt the user.

        Returns:
            bool: True if the mode is "warn" or "block".
        """
        return self.get("mode") in ["warn", "block"]

    def should_block(self) -> bool:
        """Determines if the application should block on errors.

        Returns:
            bool: True if the mode is "block".
        """
        return self.get("mode") == "block"

    def should_auto_continue(self) -> bool:
        """Determines if the application should auto-continue on warnings.

        Returns:
            bool: The value of the `auto_continue_warnings` setting.
        """
        return self.get("auto_continue_warnings")

    def _get_user_config(self) -> Dict[str, Any]:
        """Loads and returns the contents of the user config file.

        Returns:
            Dict[str, Any]: The user configuration dictionary, or an empty
            dict if the file doesn't exist or fails to parse.
        """
        if not USER_CONFIG_PATH.exists():
            return {}
        try:
            with open(USER_CONFIG_PATH, "rb") as f:
                return tomllib.load(f)
        except Exception:
            return {}

    def save_user_config(self) -> None:
        """Saves the current configuration to the user config file.

        This method persists settings that differ from the defaults, allowing
        users to maintain their customizations across sessions.

        Raises:
            IOError: If the configuration file cannot be written.
        """
        user_config = self._get_user_config()

        for key, value in self.config.items():
            if key in self.DEFAULT_CONFIG and value != self.DEFAULT_CONFIG[key]:
                user_config[key] = value
            elif key not in self.DEFAULT_CONFIG:
                user_config[key] = value

        try:
            USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            # Use tomli_w for writing, as it's a common companion to tomli.
            # Fallback to the standard `toml` library if not available.
            try:
                import tomli_w
                with open(USER_CONFIG_PATH, "wb") as f:
                    tomli_w.dump(user_config, f)
            except ImportError:
                import toml
                with open(USER_CONFIG_PATH, "w", encoding="utf-8") as f:
                    toml.dump(user_config, f)
        except Exception as e:
            raise IOError(f"Failed to save configuration to {USER_CONFIG_PATH}: {e}")

    def __str__(self) -> str:
        """Returns a string representation of the configuration.

        Returns:
            str: A string showing the current configuration state.
        """
        return f"Config({self.config})"