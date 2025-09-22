# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

"""
Validator to verify GPG signatures of packages.
"""
import os
import shutil
import requests
import gnupg
from typing import Dict, Any, Optional

from ..core.base_validator import BaseValidator
from ..core.config import Config

class CryptographicValidator(BaseValidator):
    """
    Verifies the GPG signature of a downloaded package.
    """
    name = "Cryptographic"
    category = "Cryptographic Integrity"
    description = "Verifies GPG signatures of packages."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, extracted_path: Optional[str] = None, downloaded_file_path: Optional[str] = None) -> None:
        super().__init__(pkg_name, metadata, config, extracted_path=extracted_path, downloaded_file_path=downloaded_file_path)
        self.gpg = None
        if shutil.which("gpg"):
            self.gpg = gnupg.GPG()
        else:
            self.add_warning("GPG executable not found. Install GPG with 'sudo apt install gnupg' to enable signature verification.")

    def _validate(self) -> None:
        if not self.gpg:
            return # GPG not available

        if not self.downloaded_file_path:
            self.add_info("GPG Check", "Skipped (package file not downloaded).")
            return

        # Find the metadata for the specific downloaded file
        dist_metadata = self._get_dist_metadata()
        if not dist_metadata:
            self.add_warning("Could not find release metadata for GPG check.")
            return

        if not dist_metadata.get("has_sig", False):
            self.add_info("GPG Check", "No GPG signature found for this package version.")
            return

        pkg_url = dist_metadata.get("url")
        if not pkg_url:
            self.add_warning("Could not determine package URL for GPG signature check.")
            return

        sig_url = pkg_url + ".asc"
        if not self._url_exists(sig_url):
            self.add_warning(f"GPG signature file not found at {sig_url}")
            return

        try:
            sig_response = requests.get(sig_url)
            sig_response.raise_for_status()
            sig_data = sig_response.text

            with open(self.downloaded_file_path, "rb") as f:
                verification = self.gpg.verify_file(f, data=sig_data)

            if verification.valid:
                self.add_info("GPG Signature", f"Valid signature from {verification.username} ({verification.key_id})")
            elif verification.status == 'no public key':
                self.add_warning(f"GPG signature is present, but the public key ({verification.key_id}) is not in your keyring.")
                self.add_info("GPG Key Import", f"To verify, you may need to import the key: gpg --recv-keys {verification.key_id}")
            else:
                self.add_error(f"Invalid GPG signature! Status: {verification.status}")

        except Exception as e:
            self.add_error(f"An error occurred during GPG verification: {e}")

    def _get_dist_metadata(self) -> Optional[Dict[str, Any]]:
        """Finds the metadata for the downloaded distribution file."""
        from pathlib import Path
        downloaded_file = Path(self.downloaded_file_path)
        latest_version = self.get_metadata_field("version")
        releases = self.metadata.get("releases", {})
        if not latest_version or not releases:
            return None
        dist_files = releases.get(latest_version, [])
        for f in dist_files:
            if f.get("filename") == downloaded_file.name:
                return f
        return None

    def _url_exists(self, url: str) -> bool:
        try:
            response = requests.head(url, timeout=10)
            return response.status_code == 200
        except requests.RequestException as e:
            self.add_warning(f"Could not check URL existence for {url}: {e}")
            return False
