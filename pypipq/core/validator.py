"""
Core validation pipeline for pypipq.
"""
import os
import pkgutil
import inspect
from typing import List, Dict, Any, Type
import requests

from .config import Config
from .base_validator import BaseValidator

# We need to import the validators module so pkgutil can find it.
from .. import validators as validators_package


def discover_validators() -> List[Type[BaseValidator]]:
    """
    Discover all validator classes in the 'validators' module.
    
    Returns:
        A list of validator classes.
    """
    validators = []
    
    # Path to the validators directory
    path = os.path.dirname(validators_package.__file__)

    for _, name, _ in pkgutil.iter_modules([path]):
        module = __import__(f"pypipq.validators.{name}", fromlist=["*"])
        for item_name, item in inspect.getmembers(module, inspect.isclass):
            if issubclass(item, BaseValidator) and item is not BaseValidator:
                validators.append(item)
    return validators


def validate_package(pkg_name: str, config: Config) -> Dict[str, Any]:
    """
    Fetch package metadata and run all enabled validators.
    
    Args:
        pkg_name: The name of the package to validate.
        config: The configuration object.
        
    Returns:
        A dictionary with the aggregated validation results.
    """
    # 1. Fetch metadata from PyPI
    pypi_url = config.get("pypi_url", "https://pypi.org/pypi/")
    timeout = config.get("timeout", 30)
    
    try:
        response = requests.get(f"{pypi_url}{pkg_name}/json", timeout=timeout)
        response.raise_for_status()
        metadata = response.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to fetch metadata for '{pkg_name}': {e}")

    # 2. Discover and instantiate validators
    all_validators = discover_validators()
    enabled_validators = [v(pkg_name, metadata) for v in all_validators if config.is_validator_enabled(v.name)]

    # 3. Run validators and aggregate results
    validator_results = [v.validate() for v in enabled_validators]
    aggregated_errors = [err for res in validator_results for err in res.get("errors", [])]
    aggregated_warnings = [warn for res in validator_results for warn in res.get("warnings", [])]

    return {
        "package": pkg_name,
        "errors": aggregated_errors,
        "warnings": aggregated_warnings,
        "validator_results": validator_results,
    }