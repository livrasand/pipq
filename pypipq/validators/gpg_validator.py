"""
Validator for GPG signatures.
"""
from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any

class GPGValidator(BaseValidator):
    """
    Validator that checks for GPG signatures in package releases.
    """
    name = "GPG"
    category = "Security"
    description = "Checks for GPG signatures in package releases."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        releases = self.get_metadata_field("releases", {})

        for version, release_info in releases.items():
            for file_info in release_info:
                if file_info.get("has_sig"):
                    self.add_info(f"GPG signature found for version {version}", True)
                    return

        self.add_warning("No GPG signatures found for any release.")
