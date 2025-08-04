"""
Core validation system for pypipq.

This module provides the main validation pipeline that analyzes packages
before installation using dynamically loaded validators (marshalls).
"""

import importlib
import pkgutil
import inspect
import requests
from typing import Dict, List, Any, Optional
from .base_validator import BaseValidator
from ..utils.pypi import fetch_package_metadata


def discover_validators(pkg_name: str, metadata: Dict[str, Any]) -> List[BaseValidator]:
    """
    Dynamically discover and instantiate all available validators.
    
    Args:
        pkg_name: Name of the package to validate
        metadata: Package metadata from PyPI
        
    Returns:
        List of instantiated validator objects
    """
    all_validators = []
    
    try:
        from pypipq import validators
        
        for _, modname, _ in pkgutil.iter_modules(validators.__path__):
            try:
                mod = importlib.import_module(f"pypipq.validators.{modname}")
                for _, obj in inspect.getmembers(mod, inspect.isclass):
                    if issubclass(obj, BaseValidator) and obj is not BaseValidator:
                        validator = obj(pkg_name, metadata)
                        all_validators.append(validator)
            except Exception as e:
                # Log error but continue with other validators
                print(f"Warning: Could not load validator {modname}: {e}")
                continue
                
    except ImportError:
        # No validators module found, continue with empty list
        pass
    
    return all_validators


def validate_package(pkg_name: str) -> Dict[str, Any]:
    """
    Main validation function that analyzes a package before installation.
    
    Args:
        pkg_name: Name of the package to validate
        
    Returns:
        Dictionary containing validation results with errors and warnings
    """
    try:
        # Fetch package metadata from PyPI
        metadata = fetch_package_metadata(pkg_name)
        
        # Discover and run all validators
        validators = discover_validators(pkg_name, metadata)
        
        results = {
            "package": pkg_name,
            "validators_run": len(validators),
            "errors": [],
            "warnings": [],
            "details": []
        }
        
        for validator in validators:
            try:
                validator.validate()
                result = validator.result()
                
                results["errors"].extend(result.get("errors", []))
                results["warnings"].extend(result.get("warnings", []))
                results["details"].append(result)
                
            except Exception as e:
                # Log validator error but continue
                results["warnings"].append(f"Validator {validator.name} failed: {str(e)}")
        
        return results
        
    except Exception as e:
        return {
            "package": pkg_name,
            "validators_run": 0,
            "errors": [f"Failed to validate package: {str(e)}"],
            "warnings": [],
            "details": []
        }
