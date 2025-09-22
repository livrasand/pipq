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
import logging
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

def _get_dist_url(metadata: Dict[str, Any], version: Optional[str] = None) -> str:
    """Get the URL for a specific version's distribution file, or the latest."""
    releases = metadata.get("releases", {})

    if version:
        target_version = version
    else:
        target_version = metadata.get("info", {}).get("version")

    if not target_version or target_version not in releases:
        return None

    dist_files = releases[target_version]
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

def _safe_extract(archive, extract_dir: Path) -> None:
    """Safely extract archive preventing path traversal and zip bombs."""
    MAX_SIZE = 500 * 1024 * 1024  # 500MB limit
    total_size = 0

    for member in archive.getmembers():
        # Prevent path traversal
        if member.name.startswith('/') or '..' in member.name:
            raise ValueError(f"Unsafe path: {member.name}")

        # Prevent zip bombs
        size = getattr(member, 'size', getattr(member, 'file_size', 0))
        total_size += size
        if total_size > MAX_SIZE:
            raise ValueError("Archive too large (possible zip bomb)")

        archive.extract(member, path=extract_dir)


def _download_and_extract_package(url: str, temp_dir: str) -> Tuple[Optional[str], Optional[str]]:
    logger = logging.getLogger(__name__)
    logger.info(f"Downloading and extracting package from url: {url}")
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
                _safe_extract(zip_ref, extract_dir)
        elif downloaded_file_path.name.endswith(".tar.gz"):
            with tarfile.open(downloaded_file_path, "r:gz") as tar:
                _safe_extract(tar, extract_dir)
        elif downloaded_file_path.name.endswith(".tar.bz2"):
             with tarfile.open(downloaded_file_path, "r:bz2") as tar:
                 _safe_extract(tar, extract_dir)
        else:
            return str(downloaded_file_path), None

        return str(downloaded_file_path), str(extract_dir)

    except (requests.exceptions.RequestException, tarfile.TarError, zipfile.BadZipFile, ValueError) as e:
        print(f"Warning: Could not download or extract package from {url}: {e}")
        return None, None


def validate_package(pkg_name: str, config: Config, version: Optional[str] = None, validated_packages: set = None, depth: int = 0, deep_scan: bool = False) -> Dict[str, Any]:
    logger = logging.getLogger(__name__)
    logger.info(f"Validating package: {pkg_name} version: {version} depth: {depth} deep_scan: {deep_scan}")
    """
    Fetch package metadata and run all enabled validators.
    
    Args:
        pkg_name: The name of the package to validate.
        config: The configuration object.
        version: The specific version of the package to validate. If None, latest is used.
        validated_packages: A set of already validated packages to avoid infinite recursion.
        depth: The current recursion depth.
        deep_scan: Whether to perform a deep scan including dependencies.
        
    Returns:
        A dictionary with the aggregated validation results.
    """
    if validated_packages is None:
        validated_packages = set()

    if pkg_name in validated_packages:
        return {}

    if deep_scan and depth > config.get("max_recursion_depth", 4):
        logger.warning(f"Max recursion depth reached for {pkg_name}")
        return {}

    validated_packages.add(pkg_name)

    # 1. Fetch metadata from PyPI
    pypi_url = config.get("pypi_url", "https://pypi.org/pypi/")
    timeout = config.get("timeout", 30)
    
    try:
        url = f"{pypi_url}{pkg_name}/json"
        if version:
            url = f"{pypi_url}{pkg_name}/{version}/json"

        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        metadata = response.json()
    except requests.exceptions.RequestException as e:
        if version:
             raise RuntimeError(f"Failed to fetch metadata for '{pkg_name}=={version}': {e}")
        try:
            response = requests.get(f"{pypi_url}{pkg_name}/json", timeout=timeout)
            response.raise_for_status()
            metadata = response.json()
        except requests.exceptions.RequestException:
            raise RuntimeError(f"Failed to fetch metadata for '{pkg_name}': {e}")

    validator_results = []
    with tempfile.TemporaryDirectory() as temp_dir:
        # 2. Download and extract package
        downloaded_file_path, extracted_path = None, None
        dist_url = _get_dist_url(metadata, version=version)
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

    # 5. Recursively validate dependencies (only for deep scan)
    dependency_results = []
    if deep_scan:
        dependencies = []
        for res in validator_results:
            if res.get("info", {}).get("dependencies"):
                dependencies.extend(res["info"]["dependencies"])

        for dep in dependencies:
            dep_results = validate_package(dep, config, validated_packages=validated_packages, depth=depth + 1, deep_scan=True)
            if dep_results:
                dependency_results.append(dep_results)

    return {
        "package": pkg_name,
        "errors": aggregated_errors,
        "warnings": aggregated_warnings,
        "validator_results": validator_results,
        "dependencies": dependency_results
    }