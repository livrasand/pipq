"""
Core validation pipeline for pypipq.
"""
import os
import pkgutil
import inspect
import tempfile
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Type, Tuple, Optional
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

def _get_latest_dist_url(metadata: Dict[str, Any]) -> str:
    """Get the URL for the latest distribution file."""
    releases = metadata.get("releases", {})
    latest_version = metadata.get("info", {}).get("version")
    if not latest_version or latest_version not in releases:
        return None

    dist_files = releases[latest_version]
    if not dist_files:
        return None

    # Prefer wheel files, but fall back to source distributions
    for f in dist_files:
        if f.get("packagetype") == "bdist_wheel":
            return f.get("url")

    for f in dist_files:
        if f.get("packagetype") == "sdist":
            return f.get("url")

    return dist_files[0].get("url") if dist_files else None

def _download_and_extract_package(url: str, temp_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Downloads a package and extracts it to a subdirectory."""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()

        downloaded_file_path = Path(temp_dir) / Path(url).name
        with open(downloaded_file_path, "wb") as f:
            shutil.copyfileobj(response.raw, f)

        extract_dir = Path(temp_dir) / "extracted"
        extract_dir.mkdir()

        if downloaded_file_path.name.endswith((".whl", ".zip")):
            with zipfile.ZipFile(downloaded_file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif downloaded_file_path.name.endswith(".tar.gz"):
            with tarfile.open(downloaded_file_path, "r:gz") as tar:
                tar.extractall(path=extract_dir)
        elif downloaded_file_path.name.endswith(".tar.bz2"):
             with tarfile.open(downloaded_file_path, "r:bz2") as tar:
                tar.extractall(path=extract_dir)
        else:
            return str(downloaded_file_path), None

        return str(downloaded_file_path), str(extract_dir)

    except (requests.exceptions.RequestException, tarfile.TarError, zipfile.BadZipFile) as e:
        print(f"Warning: Could not download or extract package from {url}: {e}")
        return None, None


def validate_package(pkg_name: str, config: Config, validated_packages: set = None, depth: int = 0) -> Dict[str, Any]:
    """
    Fetch package metadata and run all enabled validators.
    
    Args:
        pkg_name: The name of the package to validate.
        config: The configuration object.
        validated_packages: A set of already validated packages to avoid infinite recursion.
        depth: The current recursion depth.
        
    Returns:
        A dictionary with the aggregated validation results.
    """
    if validated_packages is None:
        validated_packages = set()

    if pkg_name in validated_packages or depth > config.get("max_recursion_depth", 3):
        return {}

    validated_packages.add(pkg_name)

    # 1. Fetch metadata from PyPI
    pypi_url = config.get("pypi_url", "https://pypi.org/pypi/")
    timeout = config.get("timeout", 30)
    
    try:
        response = requests.get(f"{pypi_url}{pkg_name}/json", timeout=timeout)
        response.raise_for_status()
        metadata = response.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to fetch metadata for '{pkg_name}': {e}")

    validator_results = []
    with tempfile.TemporaryDirectory() as temp_dir:
        # 2. Download and extract package
        downloaded_file_path, extracted_path = None, None
        dist_url = _get_latest_dist_url(metadata)
        if dist_url:
            downloaded_file_path, extracted_path = _download_and_extract_package(dist_url, temp_dir)

        # 3. Discover and instantiate validators
        all_validators = discover_validators()
        enabled_validators = [
            v(
                pkg_name,
                metadata,
                config,
                extracted_path=extracted_path,
                downloaded_file_path=downloaded_file_path
            )
            for v in all_validators
            if config.is_validator_enabled(v.name)
        ]

        # 4. Run validators and aggregate results
        validator_results = [v.validate() for v in enabled_validators]

    aggregated_errors = [err for res in validator_results for err in res.get("errors", [])]
    aggregated_warnings = [warn for res in validator_results for warn in res.get("warnings", [])]

    # 5. Recursively validate dependencies
    dependencies = []
    for res in validator_results:
        if res.get("info", {}).get("dependencies"):
            dependencies.extend(res["info"]["dependencies"])

    dependency_results = []
    for dep in dependencies:
        dep_results = validate_package(dep, config, validated_packages, depth + 1)
        if dep_results:
            dependency_results.append(dep_results)

    return {
        "package": pkg_name,
        "errors": aggregated_errors,
        "warnings": aggregated_warnings,
        "validator_results": validator_results,
        "dependencies": dependency_results
    }