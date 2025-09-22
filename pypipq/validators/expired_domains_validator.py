# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any
import whois
from datetime import datetime

class ExpiredDomainsValidator(BaseValidator):
    """
    Validator that checks for expired domains in maintainer emails.
    """
    name = "Expired Domains"
    category = "Security"
    description = "Checks for expired domains in maintainer emails."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        maintainer_email = self.get_metadata_field("maintainer_email")
        if maintainer_email:
            domain = maintainer_email.split("@")[-1]
            try:
                domain_info = whois.whois(domain)
                if isinstance(domain_info.expiration_date, list):
                    expiration_date = domain_info.expiration_date[0]
                else:
                    expiration_date = domain_info.expiration_date
                
                if expiration_date and expiration_date < datetime.now():
                    self.add_warning(f"The domain {domain} in the maintainer's email has expired.")
            except Exception as e:
                self.add_info("Domain Check", f"Could not check domain {domain}: {e}")
