"""
Package age validator.

Detects packages that are suspiciously new (potential supply chain attacks)
or very old/abandoned (potential security risks).
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from ..core.base_validator import BaseValidator


class AgeValidator(BaseValidator):
    """
    Validator that checks package age and release patterns.
    
    This validator flags packages that are:
    - Very new (less than 7 days old) - potential supply chain attacks
    - Very old with no recent updates (potential abandonment)
    - Have suspicious release patterns
    """
    
    name = "Age"
    category = "Quality"
    description = "Checks package age and release patterns"
    
    # Thresholds for age-based warnings
    NEW_PACKAGE_DAYS = 7      # Warn if package is less than this many days old
    OLD_PACKAGE_DAYS = 365 * 2  # Warn if no updates for this many days
    
    def _validate(self) -> None:
        """Check package age and release patterns."""
        upload_time = self._get_upload_time()
        if not upload_time:
            self.add_warning("Could not determine package upload time")
            return
        
        # Parse upload time
        try:
            latest_upload = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            self.add_warning("Could not parse package upload time")
            return
        
        now = datetime.now(latest_upload.tzinfo)
        days_since_upload = (now - latest_upload).days
        
        # Check if package is very new
        if days_since_upload < self.NEW_PACKAGE_DAYS:
            if days_since_upload == 0:
                self.add_warning(
                    f"Package '{self.pkg_name}' was uploaded today. "
                    f"Exercise caution with very new packages."
                )
            else:
                self.add_warning(
                    f"Package '{self.pkg_name}' was uploaded {days_since_upload} "
                    f"day{'s' if days_since_upload != 1 else ''} ago. "
                    f"Exercise caution with very new packages."
                )
        
        # Check if package hasn't been updated in a long time
        elif days_since_upload > self.OLD_PACKAGE_DAYS:
            years_old = days_since_upload // 365
            self.add_warning(
                f"Package '{self.pkg_name}' hasn't been updated in "
                f"{years_old} year{'s' if years_old != 1 else ''} "
                f"({days_since_upload} days). This may indicate an abandoned project."
            )
        
        # Analyze release patterns if we have release data
        releases = self.metadata.get("releases", {})
        if releases:
            self._analyze_release_patterns(releases, latest_upload)
        
        # Add informational data
        self.add_info("upload_time", upload_time)
        self.add_info("days_since_upload", days_since_upload)
        self.add_info("total_releases", len(releases))

    def _get_upload_time(self) -> Optional[str]:
        """
        Attempts to get the upload time from various metadata fields.
        """
        # Try 'upload_time_iso_8601' from 'info' first
        upload_time = self.get_metadata_field("upload_time_iso_8601")
        if upload_time:
            return upload_time

        # Fallback to 'upload_time' from 'info'
        upload_time = self.get_metadata_field("upload_time")
        if upload_time:
            return upload_time

        # If not found in 'info', try 'urls' for a source distribution upload time
        # This is a less reliable fallback but can sometimes provide a date
        urls = self.metadata.get("urls", [])
        for url_info in urls:
            if url_info.get("packagetype") == "sdist":
                return url_info.get("upload_time_iso_8601")
        return None
    
    def _analyze_release_patterns(self, releases: Dict[str, Any], latest_upload: datetime) -> None:
        """
        Analyze release patterns for suspicious activity.
        
        Args:
            releases: Dictionary of all package releases
            latest_upload: DateTime of the latest upload
        """
        try:
            # Count releases in the last 30 days
            thirty_days_ago = latest_upload - timedelta(days=30)
            recent_releases = 0
            
            for version, version_releases in releases.items():
                if not version_releases:
                    continue
                
                for release in version_releases:
                    upload_time_str = release.get("upload_time_iso_8601", "")
                    if upload_time_str:
                        try:
                            release_time = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
                            if release_time >= thirty_days_ago:
                                recent_releases += 1
                        except (ValueError, AttributeError):
                            continue
            
            # Flag suspicious release patterns
            if recent_releases > 10:
                self.add_warning(
                    f"Package has {recent_releases} releases in the last 30 days. "
                    f"This could indicate rapid development or potential spam."
                )
            
            # Check for version number anomalies
            version_list = list(releases.keys())
            if len(version_list) > 1:
                # Check for suspicious version jumps (like 0.1.0 to 999.999.999)
                self._check_version_anomalies(version_list)
                
        except Exception as e:
            # Don't fail the entire validation for release pattern analysis
            self.add_info("release_analysis_error", str(e))
    
    def _check_version_anomalies(self, versions: list) -> None:
        """
        Check for suspicious version number patterns.
        
        Args:
            versions: List of version strings
        """
        try:
            # Look for extremely high version numbers
            for version in versions:
                # Simple check for versions with very large numbers
                if any(part.isdigit() and int(part) > 1000 for part in version.split(".")):
                    self.add_warning(
                        f"Package has suspicious version number: {version}. "
                        f"This could indicate version squatting or other malicious activity."
                    )
                    break
                    
        except Exception:
            # Ignore errors in version analysis
            pass
