from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any

class SignaturesValidator(BaseValidator):
    """
    Validator that compares registry signatures.
    """
    name = "Signatures"
    category = "Security"
    description = "Compares registry signatures."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        # Placeholder for signature validation logic
        self.add_info("Signature Check", "Signature checking is not yet implemented.")
