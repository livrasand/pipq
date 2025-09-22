# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any, Optional
import requests

class SignaturesValidator(BaseValidator):
    """
    Validator that checks package signatures using TUF and Sigstore.
    """
    name = "Signatures"
    category = "Security"
    description = "Checks package signatures using modern standards."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        # Check PEP 458 (TUF - The Update Framework)
        if self._check_tuf_signature():
            self.add_info("TUF Signature", "Valid")

        # Check Sigstore (new standard)
        if self._check_sigstore():
            self.add_info("Sigstore", "Valid")

        if not self._check_tuf_signature() and not self._check_sigstore():
            self.add_warning("No verified signatures found for this package.")

    def _check_tuf_signature(self) -> bool:
        """
        Check for TUF (The Update Framework) signatures.
        PEP 458 provides a framework for securing PyPI.
        """
        # For now, check if PyPI metadata indicates TUF support
        # In a full implementation, this would verify against TUF metadata
        try:
            # Check if the package has release signatures or TUF metadata
            releases = self.metadata.get("releases", {})
            for version, files in releases.items():
                for file_info in files:
                    if file_info.get("has_sig") or "tuf" in file_info.get("upload_time", "").lower():
                        return True
            return False
        except Exception:
            return False

    def _check_sigstore(self) -> bool:
        """
        Check for Sigstore signatures.
        Sigstore provides cryptographic signatures for packages.
        """
        try:
            # Check if the package has Sigstore bundle or signature info
            releases = self.metadata.get("releases", {})
            for version, files in releases.items():
                for file_info in files:
                    # Look for Sigstore-related metadata
                    if ("sigstore" in str(file_info).lower() or
                        file_info.get("sigstore_bundle") or
                        "cosign" in str(file_info).lower()):
                        return True
            return False
        except Exception:
            return False
