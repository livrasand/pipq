from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any

class NewBinValidator(BaseValidator):
    """
    Validator that detects new binaries in versions.
    """
    name = "New Binaries"
    category = "Security"
    description = "Detects new binaries in versions."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        # Placeholder for new binary detection logic
        self.add_info("New Binary Check", "New binary detection is not yet implemented.")
