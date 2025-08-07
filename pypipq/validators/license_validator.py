"""
Validator to analyze package licenses.
"""
import re
from ..core.base_validator import BaseValidator


class LicenseValidator(BaseValidator):
    """
    Analyzes the package's license for potential compliance issues.
    """
    name = "License"
    category = "Legal & Compliance"
    description = "Checks for missing, ambiguous, or restrictive licenses."

    # This list could be moved to config.toml for user customization.
    # It identifies licenses that have strong "copyleft" or "viral" effects.
    RESTRICTIVE_LICENSES = [
        "AGPL", "GPL", "Affero", "General Public License", "LGPL"
    ]

    def _validate(self) -> None:
        info = self.get_metadata_field("info", {})
        license_string = info.get("license")
        classifiers = info.get("classifiers", [])

        # 1. Extract license from classifiers, which is often more reliable.
        found_licenses = set()
        is_osi_approved = False
        for classifier in classifiers:
            match = re.match(r"License :: OSI Approved :: (.*)", classifier)
            if match:
                is_osi_approved = True
                found_licenses.add(match.group(1).strip())

        # 2. Use the 'license' field as a fallback if classifiers are not specific.
        if not found_licenses and license_string and license_string.strip().upper() not in ("UNKNOWN", ""):
            found_licenses.add(license_string.strip())

        # 3. Analyze the findings.
        if not found_licenses:
            self.add_warning("No license specified or license is 'UNKNOWN'. This can create legal risks.")
            return

        license_list_str = ", ".join(sorted(list(found_licenses)))
        self.add_info("License(s)", f"{license_list_str}" + (" (OSI Approved)" if is_osi_approved else ""))

        # 4. Check against the restrictive list.
        for lic in found_licenses:
            if any(restrictive.lower() in lic.lower() for restrictive in self.RESTRICTIVE_LICENSES):
                self.add_warning(f"Uses a copyleft license ('{lic}') which may impose obligations on your project.")
                break

        self.add_info("Compatibility", "Full license compatibility analysis depends on your project's own license.")