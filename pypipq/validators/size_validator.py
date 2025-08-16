
from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any

class SizeValidator(BaseValidator):
    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)
        self.name = "Size Validator"
        self.description = "Checks for abnormally large package sizes."
        self.category = "Risk"

    def _validate(self) -> None:
        total_size = 0
        if 'releases' in self.metadata and self.metadata['releases']:
            latest_version = self.get_metadata_field('version')
            if latest_version in self.metadata['releases']:
                for release in self.metadata['releases'][latest_version]:
                    total_size += release['size']
        
        # Warn if total size is over 10MB
        if total_size > 10 * 1024 * 1024:
            self.add_warning(f"Package size is large ({total_size / 1024 / 1024:.2f} MB). This could indicate bundled binaries or other large files.")

        self.add_info("package_size", f"{total_size / 1024 / 1024:.2f} MB")

