# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

"""
Validator to check package integrity based on PyPI metadata.
"""
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional

from ..core.base_validator import BaseValidator
from ..core.config import Config


class IntegrityValidator(BaseValidator):
    """
    Validates package integrity by verifying file hashes against PyPI metadata.
    """
    name = "Integrity"
    category = "Package Integrity"
    description = "Verifies that the downloaded package's hash matches the one listed in PyPI."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, extracted_path: Optional[str] = None, downloaded_file_path: Optional[str] = None) -> None:
        super().__init__(pkg_name, metadata, config, extracted_path=extracted_path, downloaded_file_path=downloaded_file_path)

    def _validate(self) -> None:
        if not self.downloaded_file_path:
            self.add_warning("Skipping integrity check: package file not downloaded.")
            return

        downloaded_file = Path(self.downloaded_file_path)
        if not downloaded_file.is_file():
            self.add_warning(f"Skipping integrity check: downloaded file not found at {self.downloaded_file_path}")
            return

        # Find the metadata for the specific downloaded file
        latest_version = self.get_metadata_field("version")
        releases = self.metadata.get("releases", {})
        dist_files = releases.get(latest_version, [])

        dist_metadata = None
        for f in dist_files:
            if f.get("filename") == downloaded_file.name:
                dist_metadata = f
                break

        if not dist_metadata:
            self.add_warning(f"Could not find metadata for downloaded file '{downloaded_file.name}'.")
            return

        # 1. Validate URL security (HTTPS)
        url = dist_metadata.get("url")
        if url and not url.startswith("https://"):
            self.add_error(f"Insecure download URL (not HTTPS): {url}")

        # 2. Verify SHA256 hash
        expected_sha256 = dist_metadata.get("digests", {}).get("sha256")
        if not expected_sha256:
            self.add_warning("SHA256 checksum is missing from PyPI metadata. Cannot verify integrity.")
            return

        try:
            actual_sha256 = self._calculate_sha256(self.downloaded_file_path)
        except IOError as e:
            self.add_error(f"Could not read downloaded file to verify hash: {e}")
            return

        if actual_sha256.lower() != expected_sha256.lower():
            self.add_error(
                "CRITICAL: Hash mismatch! The downloaded file's SHA256 hash does not match the one from PyPI."
                f" Expected: {expected_sha256}, Got: {actual_sha256}. This could indicate a tampered package."
            )
        else:
            self.add_info("SHA256 Checksum", "OK (matches PyPI)")

        # 3. Check for GPG signature (as before)
        if not dist_metadata.get("has_sig", False):
            self.add_warning("No GPG signature found. Authenticity cannot be cryptographically verified.")
        else:
            self.add_info("GPG Signature", "Present (verification is not yet implemented).")

    def _calculate_sha256(self, filepath: str) -> str:
        """Calculate the SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()