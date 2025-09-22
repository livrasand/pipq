"""Checks for the presence of modern, verifiable package signatures.

This validator checks for evidence of two modern signing standards:
-   **TUF (The Update Framework)**: As specified in PEP 458, TUF provides a
    comprehensive security framework for repositories like PyPI.
-   **Sigstore**: A newer standard for signing, verifying, and proving the
    provenance of software artifacts.

The presence of these signatures is a strong indicator of a package's
commitment to security and integrity.
"""
from typing import Dict, Any

from ..core.base_validator import BaseValidator
from ..core.config import Config


class SignaturesValidator(BaseValidator):
    """Checks for package signatures from TUF or Sigstore.

    Note: This validator currently performs a basic check for the presence of
    signature metadata. A full implementation would involve a more complex
    verification process using TUF and Sigstore client libraries.
    """
    name = "Signatures"
    category = "Cryptographic Integrity"
    description = "Checks for modern package signatures (e.g., TUF, Sigstore)."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the SignaturesValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)

    def _validate(self) -> None:
        """Performs the signature presence checks."""
        has_tuf = self._check_tuf_signature()
        has_sigstore = self._check_sigstore()

        if has_tuf:
            self.add_info("TUF Signature", "Package appears to have TUF-related metadata (e.g., GPG signature).")
        if has_sigstore:
            self.add_info("Sigstore Signature", "Package appears to have Sigstore-related metadata.")

        if not has_tuf and not has_sigstore:
            self.add_warning("No modern cryptographic signatures (TUF or Sigstore) were found for this package.")

    def _check_tuf_signature(self) -> bool:
        """Performs a best-effort check for TUF-compatible signatures (GPG).

        A full TUF implementation requires a client, but for now, we treat the
        presence of a GPG signature (`has_sig`) as a positive signal for TUF.

        Returns:
            bool: True if a GPG signature is found, False otherwise.
        """
        try:
            releases = self.metadata.get("releases", {})
            for release_files in releases.values():
                for file_info in release_files:
                    if file_info.get("has_sig", False):
                        return True
            return False
        except (TypeError, AttributeError):
            return False

    def _check_sigstore(self) -> bool:
        """Performs a best-effort check for Sigstore signatures.

        This method looks for common keys or patterns in the release metadata
        that indicate the use of Sigstore for signing.

        Returns:
            bool: True if Sigstore metadata is found, False otherwise.
        """
        try:
            releases = self.metadata.get("releases", {})
            for release_files in releases.values():
                for file_info in release_files:
                    # Check for specific sigstore keys or 'cosign' in the file info string.
                    if (file_info.get("sigstore_bundle") or
                        "sigstore" in str(file_info).lower() or
                        "cosign" in str(file_info).lower()):
                        return True
            return False
        except (TypeError, AttributeError):
            return False
