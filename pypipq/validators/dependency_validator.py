from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any
import re

class DependencyValidator(BaseValidator):
    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)
        self.name = "Dependency Validator"
        self.description = "Analyzes package dependencies for potential security issues."
        self.category = "Risk"

    def _validate(self) -> None:
        requires_dist = self.get_metadata_field('requires_dist')
        dependencies = []
        if requires_dist:
            # Use regex to extract only the package name, removing version specifiers, semicolons, and extras
            dependencies = [p for p in (re.split(r"[<>=!~;[\] ]", d)[0] for d in requires_dist) if p]
            if len(dependencies) > 20: # Arbitrary threshold for now
                self.add_warning(f"Package has a large number of dependencies ({len(dependencies)}). This could increase the attack surface.")
        
        self.add_info("dependencies", dependencies)
