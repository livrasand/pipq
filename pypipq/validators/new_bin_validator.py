"""A placeholder validator for detecting new binary files in package updates.

The intention of this validator is to compare the contents of a new package
version against a previous one to identify if any new executable or binary
files have been added. The sudden appearance of binaries could be a security
risk (e.g., a trojan) and warrants closer inspection.
"""
from typing import Dict, Any

from ..core.base_validator import BaseValidator
from ..core.config import Config


class NewBinValidator(BaseValidator):
    """Detects the introduction of new binary files in a package version.

    Note: This validator is currently a placeholder and does not contain any
    implementation logic. Its purpose is to serve as a template for future
    development of binary analysis capabilities.
    """
    name = "NewBinaries"
    category = "Security"
    description = "Detects if a new version of a package introduces new binary files."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the NewBinValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)

    def _validate(self) -> None:
        """Performs the new binary detection (currently not implemented)."""
        self.add_info("New Binary Check", "This check is not yet implemented.")
