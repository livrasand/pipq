"""Checks for expired domains in package metadata.

This validator inspects the maintainer's email address to identify if the
associated domain has expired. An expired domain could be a security risk, as
it might be re-registered by a malicious actor for domain takeover attacks.
"""
from datetime import datetime
from typing import Dict, Any

import whois

from ..core.base_validator import BaseValidator
from ..core.config import Config


class ExpiredDomainsValidator(BaseValidator):
    """Checks for expired domains in the maintainer's email address.

    This validator uses the `whois` library to look up the expiration date of
    the domain found in the `maintainer_email` field of the package metadata.
    """
    name = "ExpiredDomains"
    category = "Security"
    description = "Checks for expired domains in maintainer and author emails."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the ExpiredDomainsValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        self.checked_domains = set()

    def _validate(self) -> None:
        """Performs the validation of domains from maintainer and author emails."""
        self._check_email_domain(self.get_metadata_field("maintainer_email"))
        self._check_email_domain(self.get_metadata_field("author_email"))

    def _check_email_domain(self, email: str) -> None:
        """Checks a single email address for an expired domain.

        Args:
            email (str): The email address to check.
        """
        if not email or "@" not in email:
            return

        domain = email.split("@")[-1].strip()
        if not domain or domain in self.checked_domains:
            return
        self.checked_domains.add(domain)

        try:
            domain_info = whois.whois(domain)
            expiration_date = domain_info.expiration_date

            # The whois library can return a single date or a list of dates.
            if isinstance(expiration_date, list):
                expiration_date = min(dt for dt in expiration_date if dt) if expiration_date else None

            if expiration_date and expiration_date < datetime.now():
                self.add_warning(
                    f"The domain '{domain}' found in the email address '{email}' "
                    "appears to be expired. This could be a security risk."
                )
            elif not expiration_date:
                self.add_info("Domain Check", f"Could not determine the expiration date for the domain '{domain}'.")

        except whois.parser.PywhoisError:
            self.add_info("Domain Check", f"Could not retrieve WHOIS information for the domain '{domain}'. It may not be a valid TLD.")
        except Exception as e:
            # Catch other potential errors during the WHOIS lookup.
            self.add_info("Domain Check", f"An unexpected error occurred while checking the domain '{domain}': {e}")
