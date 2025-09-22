"""
Base validator class that all security checks inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Config


class BaseValidator(ABC):
    """Abstract base class for all package validators.

    All validators must inherit from this class and implement the `_validate`
    method. This ensures a consistent interface for the validation pipeline,
    allowing the main `Validator` to process a list of different checks
    polymorphically.

    Attributes:
        name (str): The display name of the validator.
        category (str): A category for grouping validators (e.g., "Security").
        description (str): A brief explanation of what the validator checks.
    """

    name: str = "UnnamedValidator"
    category: str = "General"
    description: str = "No description provided"

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: "Config", extracted_path: Optional[str] = None, downloaded_file_path: Optional[str] = None) -> None:
        """Initializes the validator with package and configuration data.

        Args:
            pkg_name (str): The name of the package being validated.
            metadata (Dict[str, Any]): The package metadata fetched from the
                PyPI JSON API.
            config (Config): The application's configuration object.
            extracted_path (Optional[str]): The path to the directory where
                the package contents have been extracted. Defaults to None.
            downloaded_file_path (Optional[str]): The path to the downloaded
                package file (e.g., .whl or .tar.gz). Defaults to None.
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
        """Performs the validation check and returns the results.

        This method serves as a public interface, wrapping the internal
        `_validate` method with a try-except block to handle any unexpected
        exceptions during validation. This ensures that a single failing
        validator does not crash the entire validation pipeline.

        Returns:
            Dict[str, Any]: A dictionary containing the validation results.
        """
        try:
            self._validate()
        except Exception as e:
            self.add_error(f"Validator {self.name} failed: {str(e)}")
        return self.result()

    @abstractmethod
    def _validate(self) -> None:
        """Abstract method for implementing the core validation logic.

        Subclasses must override this method to perform their specific
        security check. The implementation should use the `add_error`,
        `add_warning`, and `add_info` methods to record its findings.
        """
        raise NotImplementedError("Subclasses must implement _validate()")

    def result(self) -> Dict[str, Any]:
        """Returns the validation results in a standardized dictionary format.

        This method compiles the findings (errors, warnings, and info) into
        a structured dictionary that can be easily processed or displayed.

        Returns:
            Dict[str, Any]: A dictionary containing the validator's name,
            category, description, and any findings.
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
        """Adds an error message to the validation results.

        An error indicates a critical issue that should block the package
        installation in "block" mode.

        Args:
            message (str): The error message to add.
        """
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        """Adds a warning message to the validation results.

        A warning indicates a potential issue that users should be aware of
        but may not be critical enough to block installation.

        Args:
            message (str): The warning message to add.
        """
        self.warnings.append(message)

    def add_info(self, key: str, value: Any) -> None:
        """Adds informational data to the validation results.

        This is used for storing supplementary data that is not an error or
        warning but provides useful context (e.g., the package's license).

        Args:
            key (str): The key for the informational data.
            value (Any): The value of the informational data.
        """
        self.info[key] = value

    def get_metadata_field(self, field: str, default: Any = None) -> Any:
        """Safely retrieves a field from the package metadata.

        This utility method provides a convenient way to access nested fields
        in the PyPI metadata dictionary without causing a `KeyError` if a
        field is missing. It checks for the common `info` sub-dictionary.

        Args:
            field (str): The name of the metadata field to retrieve.
            default (Any): The value to return if the field is not found.
                Defaults to None.

        Returns:
            Any: The value of the metadata field or the default value.
        """
        try:
            if "info" in self.metadata:
                return self.metadata["info"].get(field, default)
            return self.metadata.get(field, default)
        except (KeyError, TypeError):
            return default