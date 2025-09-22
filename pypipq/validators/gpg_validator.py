"""Checks for the presence of GPG signatures in package releases.

This validator scans the package's release history to determine if any of
the distribution files have been signed with GPG. The presence of a signature
is a positive indicator of good security practice, though this validator does
not perform the actual cryptographic verification itself.
"""
from typing import Dict, Any

from ..core.base_validator import BaseValidator
from ..core.config import Config


class GPGValidator(BaseValidator):
    """Checks if any releases of the package have GPG signatures.

    This validator iterates through all available releases in the package's
    metadata and checks the `has_sig` flag for each distribution file.
    """
    name = "GPG"
    category = "Security"
    description = "Checks for the presence of GPG signatures in package releases."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the GPGValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)

    def _validate(self) -> None:
        """Performs the check for GPG signatures."""
        releases = self.get_metadata_field("releases", {})

        if not releases:
            self.add_warning("No release information found to check for GPG signatures.")
            return

        for version, release_files in releases.items():
            for file_info in release_files:
                if file_info.get("has_sig", False):
                    self.add_info(f"GPG signature found for at least one file in version {version}.", True)
                    # We only need to find one signature to satisfy the check.
                    return

        self.add_warning("No GPG signatures were found for any release of this package.")
