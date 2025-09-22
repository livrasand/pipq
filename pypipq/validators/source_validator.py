"""Analyzes the health and activity of a package's source code repository.

A healthy, active source repository is a strong positive signal for a package's
quality and maintenance. This validator checks for a repository link and, if
it's on a supported platform like GitHub, fetches metrics such as stars, forks,
and open issues.
"""
import re
import requests
from typing import Dict, Any

from ..core.base_validator import BaseValidator
from ..core.config import Config


class SourceValidator(BaseValidator):
    """Checks the health and activity of the package's source code repository."""

    name = "Source"
    category = "Community"
    description = "Analyzes the source code repository for activity and health metrics."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the SourceValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        self.github_low_star_threshold = self.config.get("validators.Source.github_low_star_threshold", 10)
        self.github_high_issues_threshold = self.config.get("validators.Source.github_high_issues_threshold", 100)

    def _validate(self) -> None:
        """Performs the source repository validation."""
        source_url = self._find_source_url()
        if not source_url:
            self.add_warning("No source code repository URL was found in the package metadata.")
            return

        self.add_info("Source URL", source_url)

        if "github.com" in source_url:
            self._validate_github(source_url)
        elif "gitlab.com" in source_url:
            self._validate_gitlab(source_url)
        # Other platforms like Bitbucket could be added here.

    def _find_source_url(self) -> str | None:
        """Finds the most likely source repository URL from the metadata."""
        project_urls = self.get_metadata_field("project_urls", {})
        # A prioritized list of keys to search for in project_urls.
        url_keys = ["Source Code", "Source", "Repository", "Homepage", "Home"]
        for key in url_keys:
            if key in project_urls:
                return project_urls[key]
        return self.get_metadata_field("home_page")

    def _validate_github(self, url: str) -> None:
        """Fetches and analyzes metrics for a GitHub repository.

        Args:
            url (str): The URL of the GitHub repository.
        """
        match = re.search(r"github\.com/([^/]+)/([^/]+)", url)
        if not match:
            self.add_warning(f"Could not parse GitHub owner and repo from URL: {url}")
            return

        owner, repo = match.groups()
        repo = repo.removesuffix(".git")  # Clean up '.git' suffix if present.
        api_url = f"https://api.github.com/repos/{owner}/{repo}"

        try:
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            data = response.json()

            stars = data.get("stargazers_count")
            forks = data.get("forks_count")
            open_issues = data.get("open_issues_count")

            self.add_info("GitHub Stars", stars)
            self.add_info("GitHub Forks", forks)
            self.add_info("GitHub Open Issues", open_issues)

            if isinstance(stars, int) and stars < self.github_low_star_threshold:
                self.add_warning(f"Repository has fewer than {self.github_low_star_threshold} stars, indicating low community engagement.")
            if isinstance(open_issues, int) and open_issues > self.github_high_issues_threshold:
                self.add_warning(f"Repository has a high number of open issues ({open_issues}), which may indicate maintenance problems.")

        except requests.RequestException as e:
            self.add_warning(f"Failed to fetch repository data from GitHub API: {e}")

    def _validate_gitlab(self, url: str) -> None:
        """Performs a simplified check for a GitLab repository.

        Note: A full GitLab API integration is more complex as it often
        requires a project ID. This is a basic check to see if the URL is accessible.

        Args:
            url (str): The URL of the GitLab repository.
        """
        try:
            response = requests.head(url, timeout=10)
            response.raise_for_status()
            self.add_info("GitLab Project Check", "Project URL is accessible.")
        except requests.RequestException:
            self.add_warning(f"Could not access the GitLab project URL: {url}")
