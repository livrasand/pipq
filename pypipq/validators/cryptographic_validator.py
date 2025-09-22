"""Verifies the GPG signature of a downloaded package.

This validator checks if a package distribution file has an associated GPG
signature (`.asc` file) and, if so, attempts to verify it using the locally
installed GPG executable.
"""
import shutil
import requests
import gnupg
from typing import Dict, Any, Optional
from pathlib import Path

from ..core.base_validator import BaseValidator
from ..core.config import Config


class CryptographicValidator(BaseValidator):
    """Verifies the GPG signature of a downloaded package file.

    This validator requires the `gpg` command-line tool to be installed and
    in the system's PATH. It checks if the package release on PyPI is signed,
    fetches the signature file, and performs cryptographic verification.
    """
    name = "Cryptographic"
    category = "Cryptographic Integrity"
    description = "Verifies GPG signatures of packages."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, extracted_path: Optional[str] = None, downloaded_file_path: Optional[str] = None) -> None:
        """Initializes the CryptographicValidator.

        Args:
            pkg_name (str): The name of the package being validated.
            metadata (Dict[str, Any]): The package metadata.
            config (Config): The application's configuration object.
            extracted_path (Optional[str]): Path to the extracted package contents.
            downloaded_file_path (Optional[str]): Path to the downloaded package file.
        """
        super().__init__(pkg_name, metadata, config, extracted_path, downloaded_file_path)
        self.gpg: Optional[gnupg.GPG] = None
        if shutil.which("gpg"):
            self.gpg = gnupg.GPG()
        else:
            # This is an informational message, as GPG is not always required.
            self.add_info("GPG Status", "GPG executable not found, skipping signature verification.")

    def _validate(self) -> None:
        """Performs the GPG signature verification."""
        if not self.gpg:
            return  # GPG not available on the system.

        if not self.downloaded_file_path:
            self.add_info("GPG Check", "Skipped (package file not downloaded).")
            return

        dist_metadata = self._get_dist_metadata()
        if not dist_metadata:
            self.add_warning("Could not find release metadata for the downloaded file to perform GPG check.")
            return

        if not dist_metadata.get("has_sig", False):
            self.add_info("GPG Check", "No GPG signature is available for this package version on PyPI.")
            return

        pkg_url = dist_metadata.get("url")
        if not pkg_url:
            self.add_warning("Could not determine package URL for GPG signature check.")
            return

        sig_url = f"{pkg_url}.asc"
        try:
            sig_response = requests.get(sig_url, timeout=10)
            if sig_response.status_code == 404:
                self.add_warning(f"GPG signature file not found at expected URL: {sig_url}")
                return
            sig_response.raise_for_status()
            sig_data = sig_response.text

            with open(self.downloaded_file_path, "rb") as f:
                verification = self.gpg.verify_file(f, data=sig_data)

            self._process_verification_result(verification)

        except requests.RequestException as e:
            self.add_error(f"Failed to download GPG signature from {sig_url}: {e}")
        except Exception as e:
            self.add_error(f"An unexpected error occurred during GPG verification: {e}")

    def _process_verification_result(self, verification: gnupg.Verify) -> None:
        """Processes the result of the GPG verification.

        Args:
            verification (gnupg.Verify): The verification result object from python-gnupg.
        """
        if verification.valid:
            self.add_info("GPG Signature", f"Valid signature from {verification.username} ({verification.key_id})")
        elif verification.status == 'no public key':
            self.add_warning(
                f"GPG signature is present, but the public key ({verification.key_id}) is not in your local keyring."
            )
            self.add_info(
                "GPG Key Import",
                f"To verify this signature, you may need to import the key: gpg --recv-keys {verification.key_id}"
            )
        else:
            self.add_error(f"Invalid GPG signature. Status: {verification.status}")

    def _get_dist_metadata(self) -> Optional[Dict[str, Any]]:
        """Finds the metadata for the specific distribution file that was downloaded.

        Returns:
            Optional[Dict[str, Any]]: The metadata dictionary for the file, or None if not found.
        """
        if not self.downloaded_file_path:
            return None

        downloaded_filename = Path(self.downloaded_file_path).name
        # The version in 'info' is the latest, which should match the downloaded file.
        latest_version = self.get_metadata_field("version")
        releases = self.metadata.get("releases", {})

        if not latest_version or not releases:
            return None

        # Find the specific file entry in the release metadata.
        for file_info in releases.get(latest_version, []):
            if file_info.get("filename") == downloaded_filename:
                return file_info
        return None
