"""Analyzes a package's license for potential legal and compliance issues.

This validator checks for:
-   Missing or unknown licenses.
-   The presence of OSI (Open Source Initiative) approved licenses, which is
    generally a positive signal.
-   Licenses that are considered "copyleft" or "restrictive" (e.g., GPL),
    which may have implications for proprietary projects.
"""
import re
from typing import Dict, Any

from ..core.base_validator import BaseValidator
from ..core.config import Config


class LicenseValidator(BaseValidator):
    """Analyzes the package's license for potential compliance issues.

    It extracts license information primarily from the package's classifiers,
    falling back to the `license` field in the metadata.
    """
    name = "License"
    category = "Legal & Compliance"
    description = "Checks for missing, ambiguous, or restrictive licenses."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the LicenseValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        # A configurable list of licenses considered restrictive or copyleft.
        self.RESTRICTIVE_LICENSES = self.config.get("validators.License.restrictive_licenses", [
            "AGPL", "GPL", "Affero", "General Public License", "LGPL"
        ])

    def _validate(self) -> None:
        """Performs the license analysis."""
        license_string = self.get_metadata_field("license")
        classifiers = self.get_metadata_field("classifiers", [])

        found_licenses, is_osi_approved = self._extract_licenses_from_classifiers(classifiers)

        # Use the 'license' field as a fallback if classifiers are not specific.
        if not found_licenses and license_string and license_string.strip().upper() not in ("UNKNOWN", ""):
            found_licenses.add(license_string.strip())

        if not found_licenses:
            self.add_warning("No license is specified, or the license is 'UNKNOWN'. This can create legal risks.")
            return

        license_list_str = ", ".join(sorted(list(found_licenses)))
        osi_status = " (OSI Approved)" if is_osi_approved else ""
        self.add_info("License(s)", f"{license_list_str}{osi_status}")

        self._check_for_restrictive_licenses(found_licenses)
        self.add_info("Compatibility Note", "Full license compatibility analysis depends on your project's own license.")

    def _extract_licenses_from_classifiers(self, classifiers: list) -> tuple[set, bool]:
        """Extracts license information from a list of Trove classifiers.

        Args:
            classifiers (list): A list of classifier strings.

        Returns:
            tuple[set, bool]: A tuple containing a set of found license names
            and a boolean indicating if at least one is OSI approved.
        """
        found_licenses = set()
        is_osi_approved = False
        for classifier in classifiers:
            # The regex captures the license name from 'License :: OSI Approved :: ...'
            match = re.match(r"License :: OSI Approved :: (.*)", classifier)
            if match:
                is_osi_approved = True
                found_licenses.add(match.group(1).strip())
        return found_licenses, is_osi_approved

    def _check_for_restrictive_licenses(self, found_licenses: set) -> None:
        """Checks if any of the found licenses are in the restrictive list.

        Args:
            found_licenses (set): A set of license names found for the package.
        """
        for lic in found_licenses:
            if any(restrictive.lower() in lic.lower() for restrictive in self.RESTRICTIVE_LICENSES):
                self.add_warning(
                    f"The package uses a copyleft license ('{lic}'), which may "
                    "impose specific obligations on your project if you distribute it."
                )
                break  # Report only the first restrictive license found.