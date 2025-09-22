# pypipq Validator API

This document describes the API for creating custom validators in pypipq. Validators are modular security checks that analyze Python packages for potential risks and vulnerabilities.

## Overview

pypipq uses a plugin-based architecture where each security check is implemented as a validator class. All validators inherit from `BaseValidator` and implement a consistent interface for the validation pipeline.

## BaseValidator Class

All validators must inherit from `BaseValidator` located in `pypipq/core/base_validator.py`.

### Constructor

```python
def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, extracted_path: Optional[str] = None, downloaded_file_path: Optional[str] = None) -> None:
```

**Parameters:**
- `pkg_name`: Name of the package being validated
- `metadata`: Package metadata from PyPI API
- `config`: Configuration object
- `extracted_path`: Path to extracted package contents (if available)
- `downloaded_file_path`: Path to downloaded package file (if available)

### Class Attributes

```python
name: str = "UnnamedValidator"          # Unique identifier for the validator
category: str = "General"               # Category for grouping validators
description: str = "No description provided"  # Human-readable description
```

### Required Methods

#### `_validate(self) -> None`

This is the main method where you implement your validation logic. It should populate:
- `self.errors`: List of error messages (blocks installation)
- `self.warnings`: List of warning messages (may block based on config)
- `self.info`: Dictionary of additional information

**Example:**
```python
def _validate(self) -> None:
    # Check for suspicious patterns
    if self._has_suspicious_code():
        self.add_error("Package contains suspicious code patterns")

    # Add informational data
    self.add_info("code_lines", self._count_lines_of_code())
```

### Helper Methods

#### `add_error(message: str) -> None`
Add an error message that will block installation in block mode.

#### `add_warning(message: str) -> None`
Add a warning message that may prompt user or block based on configuration.

#### `add_info(key: str, value: Any) -> None`
Add informational data that will be included in the validation results.

#### `get_metadata_field(field: str, default: Any = None) -> Any`
Safely retrieve a field from package metadata.

## Creating a Custom Validator

### Step 1: Create the Validator File

Create a new file in `pypipq/validators/` with your validator class:

```python
"""
Custom validator example.
"""

from typing import Dict, Any
from ..core.base_validator import BaseValidator
from ..core.config import Config


class CustomValidator(BaseValidator):
    """
    Example custom validator that checks for specific patterns.
    """

    name = "Custom"
    category = "Security"
    description = "Checks for custom security patterns"

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)
        # Initialize any custom configuration
        self.max_file_size = self.config.get("validators.Custom.max_file_size", 1024 * 1024)

    def _validate(self) -> None:
        """Implement your validation logic here."""
        # Example: Check package size
        if self.extracted_path:
            total_size = self._calculate_total_size()
            if total_size > self.max_file_size:
                self.add_warning(f"Package size ({total_size} bytes) exceeds limit")

        # Example: Check metadata
        version = self.get_metadata_field("version")
        if version and version.startswith("0.0."):
            self.add_info("development_version", True)

    def _calculate_total_size(self) -> int:
        """Helper method to calculate total extracted size."""
        import os
        total = 0
        for root, dirs, files in os.walk(self.extracted_path):
            total += sum(os.path.getsize(os.path.join(root, file)) for file in files)
        return total
```

### Step 2: Register the Validator

Add your validator to `pypipq/validators/__init__.py`:

```python
# ... existing imports ...
from .custom_validator import CustomValidator
```

### Step 3: Configuration (Optional)

Validators can have their own configuration section. Add to your config:

```toml
[validators.Custom]
enabled = true
max_file_size = 2097152  # 2MB
```

## Validator Discovery

pypipq automatically discovers validators using Python's `pkgutil` and `inspect` modules. Any class in the `pypipq.validators` package that inherits from `BaseValidator` will be automatically loaded.

## Data Types

### Input Data

Validators receive the following data:

- **Package Metadata**: Full JSON response from PyPI API containing info, releases, urls, etc.
- **Extracted Path**: Directory containing extracted package contents (for source distributions and wheels)
- **Downloaded File Path**: Path to the downloaded package file (.whl, .tar.gz, etc.)

### Metadata Structure

Common metadata fields:
```python
{
    "info": {
        "name": "package-name",
        "version": "1.0.0",
        "summary": "Package description",
        "author": "Author Name",
        "license": "MIT",
        "classifiers": ["..."],
        "requires_dist": ["dependency>=1.0"],
        # ... more fields
    },
    "releases": {
        "1.0.0": [
            {
                "filename": "package-1.0.0.tar.gz",
                "url": "https://...",
                "hashes": {"sha256": "..."},
                "upload_time_iso_8601": "2023-01-01T00:00:00Z"
            }
        ]
    },
    "urls": [...]  # Distribution URLs
}
```

## Best Practices

### Error Handling
Always wrap validation logic in try-catch blocks to prevent one validator from breaking the entire pipeline:

```python
def _validate(self) -> None:
    try:
        # Your validation logic
        risky_operation()
    except Exception as e:
        self.add_error(f"Validation failed: {str(e)}")
```

### Performance
- Avoid expensive operations when possible
- Use caching for network requests
- Consider file size limits for large packages

### Security
- Validate all inputs and file paths
- Use safe extraction methods (provided by the framework)
- Be cautious with code execution or evaluation

### User Experience
- Provide clear, actionable error messages
- Use appropriate severity levels (error vs warning)
- Include helpful information in the `info` dict

## Configuration Integration

Validators can access configuration through `self.config`:

```python
# Get validator-specific config
timeout = self.config.get("validators.MyValidator.timeout", 30)

# Check if validator is enabled
enabled = self.config.is_validator_enabled("MyValidator")
```

## Example Validators

### File Size Validator
```python
class SizeValidator(BaseValidator):
    name = "Size"
    category = "Quality"
    description = "Checks package file sizes"

    def _validate(self) -> None:
        if not self.extracted_path:
            return

        total_size = sum(
            os.path.getsize(os.path.join(root, file))
            for root, _, files in os.walk(self.extracted_path)
            for file in files
        )

        self.add_info("total_size_bytes", total_size)

        if total_size > 50 * 1024 * 1024:  # 50MB
            self.add_warning("Package is very large (>50MB)")
```

### Dependency Validator
```python
class DependencyValidator(BaseValidator):
    name = "Dependencies"
    category = "Security"
    description = "Analyzes package dependencies"

    def _validate(self) -> None:
        requires_dist = self.get_metadata_field("requires_dist", [])

        for dep in requires_dist:
            # Parse dependency specification
            if ">" in dep or "<" in dep:
                self.add_info("pinned_dependency", dep)

        self.add_info("dependency_count", len(requires_dist))
```

## Testing Validators

Create unit tests for your validators:

```python
import unittest
from pypipq.validators.custom_validator import CustomValidator
from pypipq.core.config import Config

class TestCustomValidator(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.metadata = {"info": {"name": "test", "version": "1.0.0"}}

    def test_validation(self):
        validator = CustomValidator("test", self.metadata, self.config)
        result = validator.validate()

        self.assertIn("name", result)
        self.assertEqual(result["name"], "Custom")
```

## Distribution

To distribute your custom validators:

1. Create a separate package
2. Ensure your validators are importable
3. Document installation and configuration
4. Consider contributing back to the main project

## Advanced Topics

### Asynchronous Validation
For network-heavy validators, consider async patterns (though the current framework is synchronous).

### Custom Data Sources
Validators can integrate with external APIs, databases, or local analysis tools.

### Validator Dependencies
Validators can depend on results from other validators by checking the validation results dict.

For more examples, see the existing validators in `pypipq/validators/`.