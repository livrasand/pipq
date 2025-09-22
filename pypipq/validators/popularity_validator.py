"""Checks the download popularity of a package using the Pepy.tech API.

Package popularity can be a useful, albeit imperfect, indicator of a package's
trustworthiness and maintenance level. A widely used package is more likely
to be scrutinized by the community, and issues may be discovered and fixed
more quickly.
"""
import requests
from datetime import datetime, timedelta
from typing import Dict, Any

from ..core.base_validator import BaseValidator
from ..core.config import Config


class PopularityValidator(BaseValidator):
    """Fetches and evaluates package download statistics from Pepy.tech.

    This validator retrieves the total number of downloads and the download
    counts for the last 7 and 30 days.
    """
    name = "Popularity"
    category = "Community"
    description = "Checks the download popularity of a package via the Pepy.tech API."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the PopularityValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        self.low_popularity_threshold = self.config.get("validators.Popularity.low_popularity_threshold", 1000)

    def _validate(self) -> None:
        """Performs the popularity check."""
        api_url = f"https://api.pepy.tech/api/v2/projects/{self.pkg_name}"

        try:
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            data = response.json()

            total_downloads = data.get("total_downloads", 0)
            downloads_last_30_days = self._get_downloads_for_period(data, 30)

            self.add_info("Total Downloads", f"{total_downloads:,}")
            self.add_info("Downloads (Last 30 Days)", f"{downloads_last_30_days:,}")

            if total_downloads < self.low_popularity_threshold:
                self.add_warning(
                    f"Package has a low number of total downloads ({total_downloads}). "
                    "This may indicate it is new, niche, or not widely trusted."
                )

        except requests.RequestException as e:
            self.add_warning(f"Could not fetch package popularity data from Pepy.tech: {e}")

    def _get_downloads_for_period(self, data: dict, days: int) -> int:
        """Calculates the total downloads within a specific recent period.

        Args:
            data (dict): The API response data from Pepy.tech.
            days (int): The number of days to look back.

        Returns:
            int: The total number of downloads in the specified period.
        """
        if not data.get("downloads"):
            return 0

        since_date = datetime.now() - timedelta(days=days)
        total = 0

        # The 'downloads' key maps versions to a dictionary of daily downloads.
        for daily_downloads in data["downloads"].values():
            for date_str, count in daily_downloads.items():
                try:
                    download_date = datetime.strptime(date_str, "%Y-%m-%d")
                    if download_date >= since_date:
                        total += count
                except (ValueError, TypeError):
                    continue
        return total
