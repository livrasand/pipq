from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any, Set
import os
from pathlib import Path

class NewBinValidator(BaseValidator):
    """
    Validator that detects new binaries in versions.
    """
    name = "New Binaries"
    category = "Security"
    description = "Detects new binaries in versions."

    # Common binary file extensions
    BINARY_EXTENSIONS = {
        '.so', '.pyd', '.dll', '.exe', '.dylib', '.lib', '.a', '.o',
        '.bin', '.dat', '.pyc', '.pyo', '.pyd', '.whl'
    }

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        """Check for new binary files in the current version."""
        current_version = self.get_metadata_field("version")
        if not current_version:
            self.add_info("New Binary Check", "Could not determine current version.")
            return

        # Get files from current version
        current_files = self._get_version_files(current_version)
        if not current_files:
            self.add_info("New Binary Check", "No files found for current version.")
            return

        # Get binary files from current version
        current_binaries = self._filter_binary_files(current_files)

        if not current_binaries:
            self.add_info("New Binary Check", "No binary files found in current version.")
            return

        # Get previous versions to compare against
        previous_versions = self._get_previous_versions(current_version, limit=3)
        all_previous_binaries = set()

        for prev_version in previous_versions:
            prev_files = self._get_version_files(prev_version)
            prev_binaries = self._filter_binary_files(prev_files)
            all_previous_binaries.update(prev_binaries)

        # Find new binaries
        new_binaries = current_binaries - all_previous_binaries

        if new_binaries:
            for binary in sorted(new_binaries):
                self.add_warning(f"New binary file detected: {binary}")
        else:
            self.add_info("New Binary Check", f"No new binary files detected (checked {len(current_binaries)} binaries against {len(previous_versions)} previous versions).")

    def _get_version_files(self, version: str) -> Set[str]:
        """Get set of filenames for a specific version."""
        releases = self.metadata.get("releases", {})
        version_files = releases.get(version, [])

        filenames = set()
        for file_info in version_files:
            filename = file_info.get("filename", "")
            if filename:
                # Extract just the filename from the path
                filenames.add(os.path.basename(filename))

        return filenames

    def _filter_binary_files(self, filenames: Set[str]) -> Set[str]:
        """Filter filenames to get only binary files."""
        binaries = set()

        for filename in filenames:
            # Check for binary extensions
            if any(filename.lower().endswith(ext) for ext in self.BINARY_EXTENSIONS):
                binaries.add(filename)
                continue

            # Check for files without extensions (potential binaries)
            if '.' not in filename:
                # Additional check: if it's in a binary-like directory
                if self._is_binary_like_path(filename):
                    binaries.add(filename)

        return binaries

    def _is_binary_like_path(self, filename: str) -> bool:
        """Check if filename suggests it's a binary file."""
        # Files in directories that typically contain binaries
        binary_dirs = ['bin', 'scripts', 'lib', 'dlls', 'libs']
        path_parts = filename.lower().split('/')

        return any(part in binary_dirs for part in path_parts)

    def _get_previous_versions(self, current_version: str, limit: int = 3) -> list:
        """Get list of previous versions to compare against."""
        releases = self.metadata.get("releases", {})
        all_versions = list(releases.keys())

        # Simple version sorting (this could be improved with proper version comparison)
        try:
            all_versions.sort(key=lambda v: [int(x) for x in v.split('.') if x.isdigit()], reverse=True)
        except (ValueError, AttributeError):
            # Fallback to string sorting if version parsing fails
            all_versions.sort(reverse=True)

        # Find current version and get previous ones
        try:
            current_index = all_versions.index(current_version)
            previous_versions = all_versions[current_index + 1:current_index + 1 + limit]
        except ValueError:
            # If current version not found, take the most recent ones
            previous_versions = all_versions[:limit]

        return previous_versions
