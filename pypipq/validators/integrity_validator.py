"""
Validator to check package integrity based on PyPI metadata.
"""
from ..core.base_validator import BaseValidator


class IntegrityValidator(BaseValidator):
    """
    Validates package integrity through hashes, signatures, and secure URLs.
    """
    name = "Integrity"
    category = "Package Integrity"
    description = "Checks for checksums, GPG signatures, and secure download URLs."

    def _validate(self) -> None:
        releases = self.metadata.get("releases", {})
        latest_version = self.get_metadata_field("version")

        if not latest_version or not releases or latest_version not in releases:
            self.add_warning("Could not find release information for the latest version.")
            return

        latest_release_files = releases.get(latest_version, [])
        if not latest_release_files:
            self.add_warning(f"No distribution files found for the latest version ({latest_version}).")
            return

        # We check the first distribution file as a representative sample.
        dist_file = latest_release_files[0]

        # 1. Validate URL security (HTTPS)
        url = dist_file.get("url")
        if url and not url.startswith("https://"):
            self.add_error(f"Insecure download URL (not HTTPS): {url}")

        # 2. Verify hashes are present in metadata
        digests = dist_file.get("digests", {})
        if not digests.get("md5"):
            self.add_warning("MD5 checksum is missing from metadata.")
        if not digests.get("sha256"):
            self.add_warning("SHA256 checksum is missing. This is the recommended standard.")

        # 3. Check for GPG signature
        if not dist_file.get("has_sig", False):
            self.add_warning("No GPG signature found. Authenticity cannot be cryptographically verified.")
        else:
            self.add_info("GPG Signature", "Present (verification is not yet implemented).")

        # 4. Note on malicious file detection
        self.add_info("Malicious File Scan", "Not performed (relies on metadata only).")