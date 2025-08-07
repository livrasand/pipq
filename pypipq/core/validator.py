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

class VulnerabilityValidator(BaseValidator):
    """
    Checks for known security vulnerabilities using the OSV.dev database.

    OSV (Open Source Vulnerability) is a distributed vulnerability database
    that includes data from the Python Advisory Database (PyPA) and others,
    making it a comprehensive source.
    """
    name = "Vulnerability"
    category = "Security"
    description = "Checks for known vulnerabilities in public databases (OSV, PyPA)."

    def _validate(self) -> None:
        osv_api_url = "https://api.osv.dev/v1/query"
        # FIX: Get the canonical package name from the metadata, not from a direct attribute.
        # This makes the validator self-contained and consistent with others.
        pkg_name = self.get_metadata_field("name")
        version = self.get_metadata_field("version")

        if not pkg_name:
            self.add_warning("Could not determine package name from metadata, skipping vulnerability check.")
            return
        if not version:
            self.add_warning(f"Could not determine version for '{pkg_name}', skipping vulnerability check.")
            return

        query = {"version": version, "package": {"name": pkg_name.lower(), "ecosystem": "PyPI"}}

        try:
            # Use a reasonable timeout for the API call
            response = requests.post(osv_api_url, json=query, timeout=15)
            response.raise_for_status()
            data = response.json()

            if not data or not data.get("vulns"):
                self.add_info("Vulnerability Scan (OSV)", f"No known vulnerabilities found for v{version}.")
                return

            # Report each vulnerability as a distinct error for clarity.
            for vuln in data.get("vulns", []):
                vuln_id = vuln.get("id", "N/A")
                summary = vuln.get("summary", "No summary available.").strip()
                self.add_error(f"Vulnerability found: {vuln_id} - {summary}")

        except requests.exceptions.Timeout:
            self.add_warning("Vulnerability check timed out while contacting the OSV database.")
        except requests.exceptions.RequestException as e:
            self.add_warning(f"Could not query the OSV vulnerability database: {e}")