"""Enforces a minimum age for package releases to mitigate supply chain attacks.

A common tactic in supply chain attacks is to publish a malicious package and
hope for its immediate adoption before it can be detected. By enforcing a
"quarantine" period, this validator gives the security community time to
discover and report potentially harmful packages.
"""
from datetime import datetime
from typing import Dict, Any, Optional

from ..core.base_validator import BaseValidator
from ..core.config import Config


class ReleaseAgeValidator(BaseValidator):
    """Validator that enforces minimum release age policies.

    This validator checks the age of a package's latest release against a
    configurable policy. It supports a global default age, a list of excluded
    packages (which can use wildcards), and specific policies for individual
    packages or groups of packages.
    """

    name = "ReleaseAge"
    category = "Supply Chain Security"
    description = "Enforces a minimum age for releases to mitigate fast-moving supply chain attacks."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the ReleaseAgeValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        # Default policy (in minutes), 0 means disabled.
        self.default_min_age = self.config.get("security.minimum_release_age", 0)
        self.exclude_patterns = self.config.get("security.minimum_release_age_exclude", [])
        self.package_policies = self.config.get("security.package_policies", {})

    def _validate(self) -> None:
        """Validates the age of the current package version."""
        if self.default_min_age == 0 and not self.package_policies:
            self.add_info("Release Age Check", "Disabled globally and no specific policies are set.")
            return

        if self._is_package_excluded():
            self.add_info("Release Age Check", "Package is excluded from age restrictions.")
            return

        min_age_minutes = self._get_package_policy()
        if min_age_minutes == 0:
            self.add_info("Release Age Check", "No age restriction applies to this package.")
            return

        upload_time_str = self._get_upload_time()
        if not upload_time_str:
            self.add_warning("Could not determine the package's release time to check its age.")
            return

        try:
            release_time = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            self.add_warning(f"Could not parse the package's release time: {upload_time_str}")
            return

        now = datetime.now(release_time.tzinfo)
        age_minutes = (now - release_time).total_seconds() / 60
        required_age_hours = min_age_minutes / 60
        actual_age_hours = age_minutes / 60

        if age_minutes < min_age_minutes:
            self.add_error(
                f"Package version is too new. It was released {actual_age_hours:.1f} hours ago, "
                f"but the current policy requires a minimum age of {required_age_hours:.1f} hours. "
                "This delay helps protect against fast-moving supply chain attacks."
            )
        else:
            self.add_info("Release Age", f"OK ({actual_age_hours:.1f} hours old, policy is {required_age_hours:.1f} hours)")

    def _is_package_excluded(self) -> bool:
        """Checks if the package matches any of the exclusion patterns.

        Returns:
            bool: True if the package is excluded, False otherwise.
        """
        for pattern in self.exclude_patterns:
            if self._matches_pattern(self.pkg_name, pattern):
                return True
        return False

    def _get_package_policy(self) -> int:
        """Gets the specific age policy for this package, or the default.

        Returns:
            int: The minimum required age in minutes for the package.
        """
        # Find the most specific matching policy.
        for pattern, policy in self.package_policies.items():
            if self._matches_pattern(self.pkg_name, pattern):
                return policy.get("minimum_release_age", self.default_min_age)
        return self.default_min_age

    def _matches_pattern(self, pkg_name: str, pattern: str) -> bool:
        """Checks if a package name matches a given policy pattern.

        Supports exact matches and wildcard matches (e.g., `requests*`).

        Args:
            pkg_name (str): The name of the package.
            pattern (str): The pattern to match against.

        Returns:
            bool: True if the name matches the pattern, False otherwise.
        """
        pkg_name_lower = pkg_name.lower()
        pattern_lower = pattern.lower()
        if pattern_lower.endswith('*'):
            return pkg_name_lower.startswith(pattern_lower[:-1])
        return pkg_name_lower == pattern_lower

    def _get_upload_time(self) -> Optional[str]:
        """Gets the upload time of the package's latest version.

        Returns:
            Optional[str]: The ISO 8601 timestamp of the upload, or None.
        """
        version = self.get_metadata_field("version")
        if not version:
            return None

        releases = self.metadata.get("releases", {})
        version_files = releases.get(version, [])
        if not version_files:
            return None

        # Return the upload time of the first file listed for this version.
        return version_files[0].get("upload_time_iso_8601")