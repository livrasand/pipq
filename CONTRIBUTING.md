# Contributing to pypipq

Thank you for your interest in contributing to pypipq! We welcome contributions from the community to help improve this security tool for the Python ecosystem.

There are many opportunities to contribute to pypipq. If you want ideas, take a look at any Issues tagged with 'help wanted'.

Before your contributions can be accepted, you must:

- Sign the [pipq Individual Contributor License Agreement](https://cla-assistant.io/livrasand/pipq)
- Push your changes to your fork
- Submit a pull request

## Coding Conventions

### Python Style
- **Indentation**: Each block should consist of 4 spaces
- **Naming**: Follow PEP 8 naming conventions
  - `CamelCase` for classes
  - `snake_case` for functions and variables
  - `UPPER_CASE` for constants
- **Line Length**: Limit lines to 88 characters (Black default)
- **Imports**: Use absolute imports, group them properly
- **Type Hints**: Use type hints for function parameters and return values
- **Docstrings**: Use Google-style docstrings for all public functions and classes

### Source Code Standards
- **Encoding**: UTF-8 (without BOM)
- **Line Endings**: UNIX style (\n)
- **File Extensions**: Use .py for Python files
- **Shebang**: Include `#!/usr/bin/env python3` for executable scripts

### Code Quality
- All code must pass linting with flake8, black, and mypy
- Write comprehensive unit tests for new functionality
- Maintain test coverage above 80%
- Use descriptive commit messages

## Design Principles

### Security First
- **Client-side processing**: All analysis should be performed locally when possible
- **No external dependencies for core functionality**: Core security checks should not rely on external services
- **Privacy preservation**: Never transmit package contents or user data to external servers without explicit consent
- **Fail-safe defaults**: When in doubt, err on the side of caution

### Performance
- **Efficiency**: Keep validation times reasonable (target <5 seconds per package)
- **Caching**: Implement appropriate caching for expensive operations
- **Resource limits**: Respect memory and network limits
- **Scalability**: Design for both single packages and bulk operations

### User Experience
- **Clear messaging**: Provide actionable error and warning messages
- **Progressive disclosure**: Show essential information first, details on demand
- **Configuration flexibility**: Allow users to customize behavior
- **Backward compatibility**: Don't break existing functionality

### Maintainability
- **Modular design**: Keep validators independent and focused
- **Clear APIs**: Well-documented interfaces between components
- **Test coverage**: Comprehensive test suite
- **Documentation**: Keep docs in sync with code

## Getting Started

### Installing

pypipq uses modern Python packaging standards. You'll need:

- Python 3.8+
- pip and virtualenv
- Git

```bash
# Clone the repository
git clone https://github.com/livrasand/pypipq.git
cd pypipq

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .[dev]
```

### Development Workflow

```bash
# Install development dependencies
pip install -e .[dev]

# Run tests
pytest

# Run linting
black . --check
flake8 .
mypy .

# Format code
black .

# Run specific test
pytest tests/test_validators.py::test_age_validator
```

### Repository Structure

```
pypipq/
├── core/                    # Core framework code
│   ├── base_validator.py    # Base validator class
│   ├── config.py           # Configuration management
│   └── validator.py        # Main validation pipeline
├── validators/             # Security validators
│   ├── age.py             # Package age validation
│   ├── license_validator.py # License checking
│   └── ...                # Other validators
├── utils/                  # Utility functions
├── cli.py                  # Command-line interface
└── __init__.py

tests/                      # Test suite
docs/                       # Documentation
```

## Adding a New Validator

The easiest way to create a new validator is to use the existing `BaseValidator` class. Here's how:

### 1. Create the Validator File

Create a new file in `pypipq/validators/`:

```python
"""
Package size validator.

Checks if package size exceeds reasonable limits.
"""

from typing import Dict, Any
import os
from ..core.base_validator import BaseValidator


class SizeValidator(BaseValidator):
    """
    Validator that checks package file sizes.
    """

    name = "Size"
    category = "Quality"
    description = "Checks package file sizes for anomalies"

    def _validate(self) -> None:
        """Check package size."""
        if not self.extracted_path:
            return

        total_size = self._calculate_directory_size(self.extracted_path)

        # Check for unusually large packages
        if total_size > 100 * 1024 * 1024:  # 100MB
            self.add_error("Package is extremely large (>100MB)")

        # Check for empty packages
        elif total_size == 0:
            self.add_warning("Package appears to be empty")

        self.add_info("total_size_bytes", total_size)

    def _calculate_directory_size(self, path: str) -> int:
        """Calculate total size of all files in directory."""
        total = 0
        for root, dirs, files in os.walk(path):
            total += sum(os.path.getsize(os.path.join(root, file)) for file in files)
        return total
```

### 2. Register the Validator

Add your validator to `pypipq/validators/__init__.py`:

```python
from .size_validator import SizeValidator
```

### 3. Add Tests

Create comprehensive tests in `tests/validators/test_size_validator.py`:

```python
import unittest
from unittest.mock import patch
import tempfile
import os
from pypipq.validators.size_validator import SizeValidator
from pypipq.core.config import Config


class TestSizeValidator(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.metadata = {"info": {"name": "test-pkg", "version": "1.0.0"}}

    def test_normal_size_package(self):
        """Test validation of normal-sized package."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a small test file
            test_file = os.path.join(temp_dir, "test.py")
            with open(test_file, "w") as f:
                f.write("# Test file\n")

            validator = SizeValidator(
                "test-pkg", self.metadata, self.config, extracted_path=temp_dir
            )
            result = validator.validate()

            self.assertEqual(result["name"], "Size")
            self.assertTrue(result["info"]["total_size_bytes"] > 0)

    def test_large_package_warning(self):
        """Test detection of large packages."""
        # Test implementation for large package detection
        pass
```

### 4. Update Documentation

Add your validator to the README.md and API.md documentation.

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=pypipq --cov-report=html

# Run specific test file
pytest tests/test_validators.py

# Run tests matching pattern
pytest -k "test_age"
```

### Writing Tests

- Use `unittest` framework
- Mock external dependencies
- Test both success and failure cases
- Include edge cases
- Use descriptive test names

### Test Coverage

Maintain >80% code coverage. Check coverage reports:

```bash
pytest --cov=pypipq --cov-report=term-missing
```

## Pull Request Process

1. **Fork** the repository
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Make your changes** following the coding conventions
4. **Add tests** for new functionality
5. **Run the test suite**: `pytest`
6. **Update documentation** if needed
7. **Commit your changes**: `git commit -m "Add feature: description"`
8. **Push to your fork**: `git push origin feature/your-feature-name`
9. **Create a Pull Request**

### PR Requirements

- All tests pass
- Code is properly formatted (Black)
- No linting errors (flake8, mypy)
- Documentation updated
- Commit messages are clear and descriptive
- PR description explains the changes and why they're needed

## Issue Reporting

When reporting bugs or requesting features:

- Use the issue templates
- Provide clear reproduction steps
- Include relevant error messages/logs
- Specify your environment (Python version, OS, etc.)
- For security issues, see SECURITY.md

## Community

- **Discussions**: Use GitHub Discussions for questions
- **Issues**: Bug reports and feature requests
- **Pull Requests**: Code contributions
- **Security**: Report security issues privately

## License

By contributing to pypipq, you agree that your contributions will be licensed under the same license as the project (Apache 2.0).

## Recognition

Contributors are recognized in the project's contributor list. Significant contributions may be acknowledged in release notes.
