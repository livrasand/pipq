"""
Validator for packages maintained by a single developer.

Detects packages with only one maintainer, indicating limited community support
and higher risk of abandonment.
"""

from typing import Dict
from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any

class MaintainerValidator(BaseValidator):
    """
    Validator that checks for single maintainer projects.
    
    This validator flags packages that have only one maintainer or no
    community support, indicating a higher risk of abandonment or sporadic updates.
    """
    
    name = "Maintainer"
    category = "Quality"
    description = "Detects packages with a single maintainer or limited support"
    
    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        """Check if the package is maintained by a single individual."""
        
        # Get author and maintainer information from metadata
        author = self.get_metadata_field("author")
        author = author.strip() if isinstance(author, str) else ""
        author_email = self.get_metadata_field("author_email")
        author_email = author_email.strip() if isinstance(author_email, str) else ""
        maintainer = self.get_metadata_field("maintainer")
        maintainer = maintainer.strip() if isinstance(maintainer, str) else ""
        maintainer_email = self.get_metadata_field("maintainer_email")
        maintainer_email = maintainer_email.strip() if isinstance(maintainer_email, str) else ""
        project_urls = self.get_metadata_field("project_urls", {})

        # Heuristic to detect organization-backed projects
        org_indicators = ["pallets", "project", "foundation", "community", "organization"]
        
        # Check project URLs for organization indicators
        if project_urls and any(indicator in url.lower() for url in project_urls.values() for indicator in org_indicators):
            self.add_info("project_urls", project_urls)
            return # Likely an organization, so we can skip the rest of the checks

        # Check author/maintainer emails for organization indicators
        if any(indicator in email.lower() for email in [author_email, maintainer_email] for indicator in org_indicators):
            self.add_info("author_email", author_email)
            self.add_info("maintainer_email", maintainer_email)
            return # Likely an organization

        # Heuristic check: consider the package risky if maintainer is not specified
        # or if author is the same as the maintainer with no additional support.
        
        if not maintainer or maintainer.lower() == "none":
            self.add_warning(
                f"Package '{self.pkg_name}' is maintained solely by its author "
                f"and lacks defined community support."
            )
            
        elif maintainer == author:
            self.add_warning(
                f"Package '{self.pkg_name}' is maintained by a single individual, "
                f"'{maintainer}'."
            )
        
        # Add informational data for transparency
        self.add_info("maintainer", maintainer)
        self.add_info("maintainer_email", maintainer_email)
        self.add_info("author", author)
        self.add_info("author_email", author_email)

