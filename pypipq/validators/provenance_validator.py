"""
Validator to check package provenance information.
"""
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import os

from ..core.base_validator import BaseValidator
from ..core.config import Config


class ProvenanceValidator(BaseValidator):
    """
    Validator that verifies package provenance.
    Checks for a valid source repository URL and modern packaging standards.
    """
    name = "Provenance"
    category = "Security"
    description = "Verifies package provenance from repository and build files."

    REPUTABLE_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, extracted_path: Optional[str] = None, downloaded_file_path: Optional[str] = None) -> None:
        super().__init__(pkg_name, metadata, config, extracted_path=extracted_path, downloaded_file_path=downloaded_file_path)

    def _validate(self) -> None:
        self._check_source_repository()
        self._check_build_files()

    def _check_source_repository(self) -> None:
        """Checks for a source code repository URL."""
        project_urls = self.get_metadata_field("project_urls", {})
        homepage = self.get_metadata_field("home_page")

        source_url = project_urls.get("Source Code") or project_urls.get("Source") or project_urls.get("Repository") or homepage

        if not source_url:
            self.add_warning("No source repository URL found in package metadata.")
            return

        try:
            parsed_url = urlparse(source_url)
            if parsed_url.hostname in self.REPUTABLE_HOSTS:
                self.add_info("Source Repository", f"Package is hosted on a reputable platform: {parsed_url.hostname}")
            else:
                self.add_warning(f"Source repository is on a less common platform: {parsed_url.hostname}")
        except Exception:
            self.add_warning(f"Could not parse source repository URL: {source_url}")

    def _check_build_files(self) -> None:
        """Checks for modern build configuration files."""
        if not self.extracted_path:
            self.add_info("Build File Check", "Skipped (package not extracted).")
            return

        has_pyproject = os.path.exists(os.path.join(self.extracted_path, "pyproject.toml"))
        has_setup_cfg = os.path.exists(os.path.join(self.extracted_path, "setup.cfg"))

        if has_pyproject:
            self.add_info("Build System", "Modern (`pyproject.toml` found).")
        elif has_setup_cfg:
            self.add_info("Build System", "Traditional (`setup.cfg` found).")
        else:
            self.add_warning("No `pyproject.toml` or `setup.cfg` found. Build process may be defined imperatively in `setup.py`.")
