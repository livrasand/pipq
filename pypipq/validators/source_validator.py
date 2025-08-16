"""
Validator for source code repository health.
"""
import re
import requests
from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any

class SourceValidator(BaseValidator):
    """
    Validator that checks the health of the source code repository.
    """
    name = "Source"
    category = "Community"
    description = "Checks the health of the source code repository."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        project_urls = self.get_metadata_field("project_urls", {})
        source_url = None

        for url_name, url in project_urls.items():
            if "source" in url_name.lower() or "home" in url_name.lower():
                source_url = url
                break

        if not source_url:
            self.add_warning("No source code repository found.")
            return

        self.add_info("source_url", source_url)

        if "github.com" in source_url:
            self._validate_github(source_url)
        elif "gitlab.com" in source_url:
            self._validate_gitlab(source_url)

    def _validate_github(self, url: str) -> None:
        match = re.search(r"github.com/([^/]+)/([^/]+)", url)
        if not match:
            return

        owner, repo = match.groups()
        api_url = f"https://api.github.com/repos/{owner}/{repo}"

        try:
            response = requests.get(api_url)
            response.raise_for_status()
            data = response.json()

            self.add_info("stars", data.get("stargazers_count"))
            self.add_info("forks", data.get("forks_count"))
            self.add_info("open_issues", data.get("open_issues_count"))

        except requests.exceptions.RequestException as e:
            self.add_warning(f"Failed to fetch GitHub data: {e}")

    def _validate_gitlab(self, url: str) -> None:
        # GitLab API requires project ID, which is not always available in the URL.
        # This is a simplified implementation that checks for the project's existence.
        try:
            response = requests.get(url)
            response.raise_for_status()
            self.add_info("gitlab_project_found", True)
        except requests.exceptions.RequestException as e:
            self.add_warning(f"Failed to fetch GitLab data: {e}")
