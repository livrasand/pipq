# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

"""
Base validator class that all security checks inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Config


class BaseValidator(ABC):
    """
    Abstract base class for all package validators.
    
    All validators (marshalls) must inherit from this class and implement
    the validate() method. This provides a consistent interface for the
    validation pipeline.
    """
    
    name: str = "UnnamedValidator"
    category: str = "General"
    description: str = "No description provided"
    
    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: "Config", extracted_path: Optional[str] = None, downloaded_file_path: Optional[str] = None) -> None:
        """
        Initialize the validator with package information.
        
        Args:
            pkg_name: Name of the package being validated.
            metadata: Package metadata from PyPI API.
            config: The configuration object.
            extracted_path: The path to the extracted package contents.
            downloaded_file_path: The path to the downloaded package file.
        """
        self.pkg_name = pkg_name
        self.metadata = metadata
        self.config = config
        self.extracted_path = extracted_path
        self.downloaded_file_path = downloaded_file_path
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: Dict[str, Any] = {}
    
    def validate(self) -> Dict[str, Any]:
        """
        Perform the validation check and return results.
        
        This method wraps _validate() to ensure consistent error handling.
        """
        try:
            self._validate()
        except Exception as e:
            self.add_error(f"Validator {self.name} failed: {str(e)}")
        return self.result()
    
    @abstractmethod
    def _validate(self) -> None:
        """
        Abstract method for subclasses to implement their validation logic.
        
        This method should populate self.errors, self.warnings, and self.info.
        """
        raise NotImplementedError("Subclasses must implement _validate()")
    
    def result(self) -> Dict[str, Any]:
        """
        Return the validation results in a standardized format.
        
        Returns:
            Dictionary containing validation results
        """
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "errors": self.errors,
            "warnings": self.warnings,
            "info": self.info,
        }
    
    def add_error(self, message: str) -> None:
        """Add an error message to the results."""
        self.errors.append(message)
    
    def add_warning(self, message: str) -> None:
        """Add a warning message to the results."""
        self.warnings.append(message)
    
    def add_info(self, key: str, value: Any) -> None:
        """Add informational data to the results."""
        self.info[key] = value
    
    def get_metadata_field(self, field: str, default: Any = None) -> Any:
        """
        Safely get a field from package metadata.
        
        Args:
            field: Field name to retrieve
            default: Default value if field doesn't exist
            
        Returns:
            Field value or default
        """
        try:
            if "info" in self.metadata:
                return self.metadata["info"].get(field, default)
            return self.metadata.get(field, default)
        except (KeyError, TypeError):
            return default