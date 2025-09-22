"""Validates the age and release history of a package.

This validator checks for several time-based and release-related red flags:
-   **New Packages**: Packages that were uploaded very recently, which can be
    a characteristic of supply chain attacks.
-   **Old Packages**: Packages that have not been updated in a long time,
    suggesting they may be abandoned and unmaintained.
-   **Release Spam**: An unusually high number of releases in a short period.
-   **Version Anomalies**: Suspiciously large jumps or formats in version
    numbers.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from ..core.base_validator import BaseValidator
from ..core.config import Config


class AgeValidator(BaseValidator):
    """Checks the age of a package's latest release and its update frequency.

    This validator assesses the temporal aspects of a package to identify
    potential risks associated with its age and maintenance status.
    """

    name = "Age"
    category = "Quality"
    description = "Checks package age and release patterns."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the AgeValidator.

        Args:
            pkg_name (str): The name of the package being validated.
            metadata (Dict[str, Any]): The package metadata.
            config (Config): The application's configuration object.
            **kwargs: Additional keyword arguments.
        """
        super().__init__(pkg_name, metadata, config, **kwargs)
        self.NEW_PACKAGE_DAYS = self.config.get("validators.Age.new_package_days", 7)
        self.OLD_PACKAGE_DAYS = self.config.get("validators.Age.old_package_days", 365 * 2)

    def _validate(self) -> None:
        """Performs the age and release pattern validation."""
        upload_time_str = self._get_upload_time()
        if not upload_time_str:
            self.add_warning("Could not determine the package's upload time.")
            return

        try:
            # The 'Z' suffix indicates UTC, which fromisoformat can handle directly since Python 3.11.
            # For broader compatibility, we replace it with the UTC offset.
            upload_time = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            self.add_warning(f"Could not parse the package's upload time: {upload_time_str}")
            return

        now = datetime.now(upload_time.tzinfo)
        days_since_upload = (now - upload_time).days

        self._check_if_new(days_since_upload)
        self._check_if_old(days_since_upload)

        releases = self.metadata.get("releases", {})
        if releases:
            self._analyze_release_patterns(releases, upload_time)

        self.add_info("upload_time", upload_time_str)
        self.add_info("days_since_upload", days_since_upload)
        self.add_info("total_releases", len(releases))

    def _check_if_new(self, days_since_upload: int) -> None:
        """Checks if the package is suspiciously new."""
        if days_since_upload < self.NEW_PACKAGE_DAYS:
            message = (
                f"Package '{self.pkg_name}' was uploaded today. "
                if days_since_upload == 0
                else (
                    f"Package '{self.pkg_name}' was uploaded {days_since_upload} "
                    f"day{'s' if days_since_upload != 1 else ''} ago. "
                )
            )
            self.add_warning(f"{message}Exercise caution with very new packages.")

    def _check_if_old(self, days_since_upload: int) -> None:
        """Checks if the package has not been updated in a long time."""
        if days_since_upload > self.OLD_PACKAGE_DAYS:
            years_old = days_since_upload // 365
            self.add_warning(
                f"Package '{self.pkg_name}' has not been updated in "
                f"{years_old} year{'s' if years_old != 1 else ''} "
                f"({days_since_upload} days). This may indicate an abandoned project."
            )

    def _get_upload_time(self) -> Optional[str]:
        """Retrieves the upload time from various metadata fields.

        It prioritizes the ISO 8601 format and falls back to other fields if
        the primary one is not available.

        Returns:
            Optional[str]: The ISO 8601 formatted upload time string, or None.
        """
        # Primary field from the 'info' dictionary.
        upload_time = self.get_metadata_field("upload_time_iso_8601")
        if upload_time:
            return upload_time

        # Fallback to the older 'upload_time' field.
        upload_time = self.get_metadata_field("upload_time")
        if upload_time:
            return upload_time

        # As a last resort, check the upload time of the source distribution.
        urls = self.metadata.get("urls", [])
        for url_info in urls:
            if url_info.get("packagetype") == "sdist":
                return url_info.get("upload_time_iso_8601")
        return None

    def _analyze_release_patterns(self, releases: Dict[str, Any], latest_upload: datetime) -> None:
        """Analyzes release history for suspicious patterns.

        Args:
            releases (Dict[str, Any]): A dictionary of all package releases.
            latest_upload (datetime): The timestamp of the latest upload.
        """
        try:
            # Check for a high frequency of recent releases.
            thirty_days_ago = latest_upload - timedelta(days=30)
            recent_release_count = 0
            for version_releases in releases.values():
                for release in version_releases:
                    upload_time_str = release.get("upload_time_iso_8601")
                    if upload_time_str:
                        try:
                            release_time = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
                            if release_time >= thirty_days_ago:
                                recent_release_count += 1
                        except (ValueError, AttributeError):
                            continue

            if recent_release_count > 10:
                self.add_warning(
                    f"Package has {recent_release_count} releases in the last 30 days. "
                    "This could indicate rapid development or potential spam."
                )

            # Check for anomalies in version numbers.
            version_list = list(releases.keys())
            if len(version_list) > 1:
                self._check_version_anomalies(version_list)
        except Exception as e:
            self.add_info("release_analysis_error", str(e))

    def _check_version_anomalies(self, versions: list) -> None:
        """Checks for suspicious patterns in version numbers, like large jumps.

        Args:
            versions (list): A list of version strings for the package.
        """
        try:
            for version in versions:
                # A simple heuristic to detect absurdly high version numbers.
                parts = version.split('.')
                if any(part.isdigit() and int(part) > 1000 for part in parts):
                    self.add_warning(
                        f"Package has a suspicious version number: {version}. "
                        "This could indicate version squatting or malicious activity."
                    )
                    break  # Report only the first anomaly found.
        except (ValueError, TypeError):
            # Ignore errors during version parsing, as it's a best-effort check.
            pass
