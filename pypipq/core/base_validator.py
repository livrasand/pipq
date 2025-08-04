"""
Base validator class that all security checks inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional


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
    
    def __init__(self, pkg_name: str, metadata: Dict[str, Any]) -> None:
        """
        Initialize the validator with package information.
        
        Args:
            pkg_name: Name of the package being validated
            metadata: Package metadata from PyPI API
        """
        self.pkg_name = pkg_name
        self.metadata = metadata
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: Dict[str, Any] = {}
    
    @abstractmethod
    def validate(self) -> None:
        """
        Perform the validation check.
        
        This method should populate self.errors and self.warnings lists
        based on the analysis results.
        """
        raise NotImplementedError("Subclasses must implement validate()")
    
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
