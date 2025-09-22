"""
Validator for package popularity.
"""
import requests
from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any

class PopularityValidator(BaseValidator):
    """
    Validator that checks the popularity of a package.
    """
    name = "Popularity"
    category = "Community"
    description = "Checks the popularity of a package."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        api_key = self.config.get("api_keys.pepy_tech")
        if not api_key:
            self.add_info("Popularity Check", "Premium option: Register at pepy.tech, generate an API key, and configure it in ~/.config/pipq/config.toml as 'api_keys.pepy_tech' for download statistics.")
            return

        api_url = f"https://api.pepy.tech/api/v2/projects/{self.pkg_name}"

        try:
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()
            data = response.json()

            self.add_info("total_downloads", data.get("total_downloads"))
            self.add_info("downloads_last_30_days", self._get_downloads_for_period(data, 30))
            self.add_info("downloads_last_7_days", self._get_downloads_for_period(data, 7))

        except requests.exceptions.RequestException as e:
            self.add_warning(f"Failed to fetch popularity data: {e}")

    def _get_downloads_for_period(self, data: dict, days: int) -> int:
        if not data.get("downloads"):
            return 0

        total = 0
        for version, downloads in data["downloads"].items():
            for date, count in downloads.items():
                total += count
        return total
