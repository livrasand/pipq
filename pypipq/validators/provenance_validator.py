"""Verifies the provenance of a package.

This validator assesses the origin and trustworthiness of a package by:
-   Checking for a link to a source code repository.
-   Identifying if the repository is hosted on a well-known, reputable platform
    (e.g., GitHub, GitLab).
-   Inspecting the package contents for modern, declarative build files like
    `pyproject.toml`, which are generally safer than imperative `setup.py` files.
"""
import os
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from ..core.base_validator import BaseValidator
from ..core.config import Config


class ProvenanceValidator(BaseValidator):
    """Verifies package provenance by checking for a source repository and modern build files.

    A clear link to a source repository on a reputable host increases trust
    and allows for manual inspection of the code. The use of modern packaging
    standards like `pyproject.toml` is also a positive signal.
    """
    name = "Provenance"
    category = "Security"
    description = "Verifies package provenance from its repository and build files."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the ProvenanceValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        self.REPUTABLE_HOSTS = self.config.get("validators.Provenance.reputable_hosts", {
            "github.com", "gitlab.com", "bitbucket.org"
        })

    def _validate(self) -> None:
        """Performs the provenance checks."""
        self._check_source_repository()
        self._check_build_files()

    def _check_source_repository(self) -> None:
        """Checks for a source code repository URL and its host."""
        project_urls = self.get_metadata_field("project_urls", {})
        homepage = self.get_metadata_field("home_page")

        # Try to find a source URL from common keys in project_urls, falling back to the homepage.
        source_url = (
            project_urls.get("Source Code")
            or project_urls.get("Source")
            or project_urls.get("Repository")
            or homepage
        )

        if not source_url:
            self.add_warning("No source repository URL could be found in the package metadata.")
            return

        self.add_info("Source URL", source_url)

        try:
            parsed_url = urlparse(source_url)
            hostname = parsed_url.hostname
            if not hostname:
                self.add_warning(f"Could not parse a valid hostname from the source URL: {source_url}")
                return

            if hostname in self.REPUTABLE_HOSTS:
                self.add_info("Source Host", f"Package is hosted on a reputable platform: {hostname}")
            else:
                self.add_warning(f"Source repository is hosted on a less common platform: {hostname}")
        except (ValueError, TypeError):
            self.add_warning(f"Could not parse the source repository URL: {source_url}")

    def _check_build_files(self) -> None:
        """Checks for the presence of modern build configuration files."""
        if not self.extracted_path:
            self.add_info("Build File Check", "Skipped because the package was not extracted.")
            return

        has_pyproject = os.path.exists(os.path.join(self.extracted_path, "pyproject.toml"))
        has_setup_cfg = os.path.exists(os.path.join(self.extracted_path, "setup.cfg"))
        has_setup_py = os.path.exists(os.path.join(self.extracted_path, "setup.py"))

        if has_pyproject:
            self.add_info("Build System", "Modern (`pyproject.toml` was found).")
        elif has_setup_cfg:
            self.add_info("Build System", "Traditional (`setup.cfg` was found).")
        elif has_setup_py:
            self.add_warning(
                "No `pyproject.toml` or `setup.cfg` was found. The build process may be defined "
                "imperatively in `setup.py`, which is less transparent."
            )
        else:
            self.add_warning("No standard Python build files were found in the package.")
