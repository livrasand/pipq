"""Checks for abnormally large package sizes.

An unusually large package size can be a red flag, as it may indicate the
inclusion of unnecessary large assets, bundled binaries, or potentially
maliciously padded files. This validator checks the total size of all
distribution files for the latest release against a configurable threshold.
"""
from typing import Dict, Any

from ..core.base_validator import BaseValidator
from ..core.config import Config


class SizeValidator(BaseValidator):
    """Checks the total size of a package's latest release files."""

    name = "Size"
    category = "Quality"
    description = "Checks for abnormally large package sizes, which could indicate bundled binaries."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the SizeValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        self.max_size_mb = self.config.get("validators.Size.max_size_mb", 20)

    def _validate(self) -> None:
        """Performs the package size validation."""
        latest_version = self.get_metadata_field('version')
        if not latest_version:
            self.add_warning("Could not determine the latest version to check package size.")
            return

        releases = self.metadata.get('releases', {})
        release_files = releases.get(latest_version, [])
        if not release_files:
            self.add_warning(f"No release files found for the latest version ({latest_version}).")
            return

        total_size = sum(file_info.get('size', 0) for file_info in release_files)
        total_size_mb = total_size / (1024 * 1024)

        self.add_info("Total Release Size", f"{total_size_mb:.2f} MB")

        if total_size_mb > self.max_size_mb:
            self.add_warning(
                f"Package release is unusually large ({total_size_mb:.2f} MB). "
                f"This could indicate the presence of bundled binaries or other large, unexpected files."
            )
