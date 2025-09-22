"""Analyzes the maintainer information of a package.

This validator checks if a package appears to be maintained by a single
individual, which can be a risk factor. A project with a single maintainer is
more susceptible to abandonment and may lack the peer review and support of a
larger community or organization.
"""
from typing import Dict, Any

from ..core.base_validator import BaseValidator
from ..core.config import Config


class MaintainerValidator(BaseValidator):
    """Checks for packages that appear to have a single maintainer.

    This validator uses heuristics to determine if a project is backed by an
    organization or a community. If not, it checks if the author and maintainer
    are the same, which suggests a single point of failure.
    """

    name = "Maintainer"
    category = "Quality"
    description = "Detects packages with a single maintainer or limited community support."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the MaintainerValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        # Keywords that suggest a project is backed by an organization.
        self.ORG_INDICATORS = self.config.get("validators.Maintainer.org_indicators", [
            "pallets", "project", "foundation", "community", "organization", "labs", "inc"
        ])

    def _validate(self) -> None:
        """Performs the check for single-maintainer projects."""
        author = str(self.get_metadata_field("author", "")).strip()
        author_email = str(self.get_metadata_field("author_email", "")).strip()
        maintainer = str(self.get_metadata_field("maintainer", "")).strip()
        maintainer_email = str(self.get_metadata_field("maintainer_email", "")).strip()
        project_urls = self.get_metadata_field("project_urls", {})

        # Add maintainer info for transparency, regardless of the outcome.
        self.add_info("author", author or "Not specified")
        self.add_info("author_email", author_email or "Not specified")
        self.add_info("maintainer", maintainer or "Not specified")
        self.add_info("maintainer_email", maintainer_email or "Not specified")

        # Heuristic 1: Check project URLs for organization indicators.
        if project_urls and any(
            indicator in url.lower() for url in project_urls.values() for indicator in self.ORG_INDICATORS
        ):
            self.add_info("Maintainer Status", "Likely maintained by an organization (based on project URLs).")
            return

        # Heuristic 2: Check author/maintainer names and emails for indicators.
        combined_info = f"{author} {author_email} {maintainer} {maintainer_email}".lower()
        if any(indicator in combined_info for indicator in self.ORG_INDICATORS):
            self.add_info("Maintainer Status", "Likely maintained by an organization (based on author/maintainer info).")
            return

        # Heuristic 3: Check if the project has a sole maintainer.
        # This is triggered if maintainer is not specified, or is the same as the author.
        if not maintainer or maintainer.lower() in (author.lower(), "none", ""):
            self.add_warning(
                f"Package '{self.pkg_name}' appears to be maintained by a single individual or lacks "
                "explicit community support, which can be a risk factor."
            )
        elif author and maintainer and author.lower() != maintainer.lower():
             self.add_info("Maintainer Status", f"The package has a distinct author ({author}) and maintainer ({maintainer}).")
        else:
            self.add_info("Maintainer Status", f"The package is maintained by '{maintainer}'.")
