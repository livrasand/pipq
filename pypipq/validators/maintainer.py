"""
Validator for packages maintained by a single developer.

Detects packages with only one maintainer, indicating limited community support
and higher risk of abandonment.
"""

from typing import Dict
from ..core.base_validator import BaseValidator


class MaintainerValidator(BaseValidator):
    """
    Validator that checks for single maintainer projects.
    
    This validator flags packages that have only one maintainer or no
    community support, indicating a higher risk of abandonment or sporadic updates.
    """
    
    name = "Maintainer"
    category = "Quality"
    description = "Detects packages with a single maintainer or limited support"
    
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
        
        # Additional community checks could be implemented here
        # based on additional metadata such as contributor count,
        # repository stars, forks, etc.
        
        # self.check_github_support()

    # def check_github_support(self):
    #    "Perform GitHub repository analysis if possible"
    #    pass

