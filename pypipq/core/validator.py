"""
Core validation system for pypipq.

This module provides the main validation pipeline that analyzes packages
before installation using dynamically loaded validators.
"""

import importlib
import pkgutil
import inspect
from typing import Dict, List, Any, Optional
from .base_validator import BaseValidator
from .config import Config
from ..utils.pypi import fetch_package_metadata

def discover_validators(
    config: Config, pkg_name: str, metadata: Dict[str, Any]
) -> List[BaseValidator]:
    """
    Dynamically discover and instantiate all available validators.
    
    Args:
        config: The configuration object.
        pkg_name: The name of the package being validated.
        metadata: The package metadata from the PyPI API.
        
    Returns:
        List of instantiated validator objects.
    """
    all_validators = []
    try:
        from pypipq import validators
        
        for _, modname, _ in pkgutil.iter_modules(validators.__path__):
            try:
                mod = importlib.import_module(f"pypipq.validators.{modname}")
                for _, obj in inspect.getmembers(mod, inspect.isclass):
                    if issubclass(obj, BaseValidator) and obj is not BaseValidator:
                        validator_name = obj.__name__.replace("Validator", "").lower()
                        if config.is_validator_enabled(validator_name):
                            all_validators.append(obj(pkg_name, metadata))
            except Exception as e:
                print(f"Warning: Could not load validator {modname}: {e}")
                continue
    except ImportError:
        pass
    
    return all_validators

def validate_package(package_name: str, config: Config) -> Dict[str, Any]:
    """
    Main validation function that analyzes a package before installation.
    
    Args:
        package_name: Name of the package to validate.
        config: The configuration object.

    Returns:
        Dictionary containing validation results.
    """
    print("Validating request...")
    metadata = fetch_package_metadata(package_name)
    if not metadata:
        return {
            "package": package_name,
            "error": "Could not fetch package metadata from PyPI.",
        }

    package_version = metadata.get("info", {}).get("version", "unknown")
    validators = discover_validators(config, package_name, metadata)
    results = {
        "package": f"{package_name}=={package_version}",
        "validators_run": len(validators),
        "errors": [],
        "warnings": [],
        "info": {},
        "validator_results": [],
    }

    for validator in validators:
        try:
            validator.validate()
            val_result = validator.result()
            results["validator_results"].append(val_result)
            results["errors"].extend(val_result["errors"])
            results["warnings"].extend(val_result["warnings"])
            results["info"].update(val_result["info"])
        except Exception as e:
            results["errors"].append(f"Validator '{validator.name}' threw an exception: {e}")

    return results