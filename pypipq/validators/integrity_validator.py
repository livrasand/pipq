"""Verifies the integrity of a downloaded package file.

This validator performs several crucial checks to ensure the downloaded file
is authentic and has not been tampered with:
-   It verifies that the download URL uses HTTPS.
-   It calculates the SHA256 hash of the downloaded file and compares it
    with the hash provided in the PyPI metadata.
-   It checks for the presence of a GPG signature.
"""
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional

from ..core.base_validator import BaseValidator
from ..core.config import Config


class IntegrityValidator(BaseValidator):
    """Validates package integrity by verifying file hashes against PyPI metadata.

    This is a critical security check to protect against package tampering
    during the download process (man-in-the-middle attacks).
    """
    name = "Integrity"
    category = "Package Integrity"
    description = "Verifies that the downloaded package's hash matches the one listed in PyPI."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the IntegrityValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)

    def _validate(self) -> None:
        """Performs the integrity validation checks."""
        if not self.downloaded_file_path:
            self.add_info("Integrity Check", "Skipped (package file not downloaded).")
            return

        downloaded_file = Path(self.downloaded_file_path)
        if not downloaded_file.is_file():
            self.add_warning(f"Skipping integrity check: downloaded file not found at '{self.downloaded_file_path}'.")
            return

        dist_metadata = self._find_dist_metadata(downloaded_file.name)
        if not dist_metadata:
            self.add_warning(f"Could not find release metadata for the file '{downloaded_file.name}' to verify integrity.")
            return

        self._check_url_security(dist_metadata.get("url"))
        self._verify_sha256_hash(dist_metadata.get("digests", {}))
        self._check_gpg_signature(dist_metadata)

    def _find_dist_metadata(self, filename: str) -> Optional[Dict[str, Any]]:
        """Finds the metadata for a specific distribution file from the release info.

        Args:
            filename (str): The name of the file to find.

        Returns:
            Optional[Dict[str, Any]]: The metadata dictionary for the file, or None if not found.
        """
        latest_version = self.get_metadata_field("version")
        releases = self.metadata.get("releases", {})
        if not latest_version or not releases:
            return None

        for file_info in releases.get(latest_version, []):
            if file_info.get("filename") == filename:
                return file_info
        return None

    def _check_url_security(self, url: Optional[str]) -> None:
        """Checks if the download URL uses HTTPS."""
        if url and not url.lower().startswith("https://"):
            self.add_error(f"Insecure download URL (does not use HTTPS): {url}")

    def _verify_sha256_hash(self, digests: Dict[str, str]) -> None:
        """Verifies the SHA256 hash of the downloaded file."""
        expected_sha256 = digests.get("sha256")
        if not expected_sha256:
            self.add_warning("SHA256 checksum is missing from PyPI metadata; integrity cannot be verified.")
            return

        try:
            actual_sha256 = self._calculate_sha256(self.downloaded_file_path)
        except IOError as e:
            self.add_error(f"Could not read the downloaded file to verify its hash: {e}")
            return

        if actual_sha256.lower() != expected_sha256.lower():
            self.add_error(
                "CRITICAL: The downloaded file's hash does not match the one from PyPI. "
                "This could indicate a tampered package (man-in-the-middle attack). "
                f"Expected: {expected_sha256}, Got: {actual_sha256}."
            )
        else:
            self.add_info("SHA256 Checksum", "OK (matches PyPI metadata)")

    def _check_gpg_signature(self, dist_metadata: Dict[str, Any]) -> None:
        """Checks for the presence of a GPG signature."""
        if dist_metadata.get("has_sig", False):
            self.add_info("GPG Signature", "A GPG signature is available for this file.")
        else:
            self.add_warning("No GPG signature is available for this file.")

    def _calculate_sha256(self, filepath: str) -> str:
        """Calculates the SHA256 hash of a file efficiently.

        Args:
            filepath (str): The path to the file.

        Returns:
            str: The hex digest of the SHA256 hash.
        """
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            # Read and update the hash in chunks to handle large files.
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()