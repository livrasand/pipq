"""Handles the core validation pipeline for pypipq.

This module orchestrates the package validation process, which includes:
1.  Discovering all available `BaseValidator` implementations.
2.  Fetching package metadata from the Python Package Index (PyPI).
3.  Downloading and extracting the package distribution file.
4.  Running all enabled validators concurrently.
5.  Aggregating the results and, if specified, recursively validating
    dependencies.
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
from concurrent.futures import ThreadPoolExecutor

from .config import Config
from .base_validator import BaseValidator
from .. import validators as validators_package

# Initialize a logger for this module.
logger = logging.getLogger(__name__)


def discover_validators() -> List[Type[BaseValidator]]:
    """Discovers all validator classes within the `pypipq.validators` module.

    This function iterates through the modules in the `validators` package,
    inspects their members, and collects all classes that are subclasses of
    `BaseValidator` (excluding `BaseValidator` itself).

    Returns:
        List[Type[BaseValidator]]: A list of the discovered validator classes.
    """
    validators = []
    path = os.path.dirname(validators_package.__file__)

    for _, name, _ in pkgutil.iter_modules([path]):
        try:
            module = __import__(f"pypipq.validators.{name}", fromlist=["*"])
            for _, item in inspect.getmembers(module, inspect.isclass):
                if issubclass(item, BaseValidator) and item is not BaseValidator:
                    validators.append(item)
        except ImportError as e:
            logger.warning(f"Could not import validator module {name}: {e}")
    return validators


def _get_dist_url(metadata: Dict[str, Any], version: Optional[str] = None) -> Optional[str]:
    """Finds the distribution file URL for a package version.

    It prioritizes wheel (`bdist_wheel`) files but falls back to source
    distributions (`sdist`) if no wheel is available.

    Args:
        metadata (Dict[str, Any]): The package metadata from PyPI.
        version (Optional[str]): The specific version to look for. If None,
            the latest version is used.

    Returns:
        Optional[str]: The URL of a suitable distribution file, or None if
        not found.
    """
    releases = metadata.get("releases", {})
    target_version = version or metadata.get("info", {}).get("version")

    if not target_version or target_version not in releases:
        return None

    dist_files = releases.get(target_version, [])
    if not dist_files:
        return None

    # Prefer wheels, then source distributions.
    for f in dist_files:
        if f.get("packagetype") == "bdist_wheel":
            return f.get("url")
    for f in dist_files:
        if f.get("packagetype") == "sdist":
            return f.get("url")

    return dist_files[0].get("url") if dist_files else None


def _safe_extract(archive, extract_dir: Path) -> None:
    """Safely extracts an archive, guarding against path traversal and zip bombs.

    Args:
        archive: A `zipfile.ZipFile` or `tarfile.TarFile` object.
        extract_dir (Path): The directory to extract files into.

    Raises:
        ValueError: If an unsafe path or an excessively large archive is
            detected.
    """
    MAX_SIZE = 500 * 1024 * 1024  # 500 MB limit
    total_size = 0

    members = archive.getmembers() if hasattr(archive, 'getmembers') else archive.infolist()
    for member in members:
        member_name = member.name if hasattr(member, 'name') else member.filename
        if member_name.startswith('/') or '..' in member_name:
            raise ValueError(f"Unsafe path detected in archive: {member_name}")

        size = member.size if hasattr(member, 'size') else member.file_size
        total_size += size
        if total_size > MAX_SIZE:
            raise ValueError("Archive exceeds maximum size limit (possible zip bomb).")

        archive.extract(member, path=extract_dir)


def _download_and_extract_package(url: str, temp_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """Downloads and extracts a package file to a temporary directory.

    Args:
        url (str): The URL of the package file to download.
        temp_dir (str): The path to the temporary directory.

    Returns:
        Tuple[Optional[str], Optional[str]]: A tuple containing the path to
        the downloaded file and the path to the extraction directory. Returns
        (None, None) on failure.
    """
    logger.info(f"Downloading and extracting package from: {url}")
    try:
        response = requests.get(url, stream=True, timeout=30)
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
            # If the file type is unknown, we can't extract it.
            return str(downloaded_file_path), None

        return str(downloaded_file_path), str(extract_dir)

    except (requests.RequestException, tarfile.TarError, zipfile.BadZipFile, ValueError, IOError) as e:
        logger.error(f"Could not download or extract package from {url}: {e}")
        return None, None


def validate_package(
    pkg_name: str,
    config: Config,
    version: Optional[str] = None,
    validated_packages: Optional[set] = None,
    depth: int = 0,
    deep_scan: bool = False,
) -> Dict[str, Any]:
    """Fetches package metadata and runs all enabled validators.

    This is the main entry point for validating a single package. It handles
    fetching data, orchestrating validators, and optionally performing a
    recursive scan of dependencies.

    Args:
        pkg_name (str): The name of the package to validate.
        config (Config): The application's configuration object.
        version (Optional[str]): A specific version to validate. If None, the
            latest version is used.
        validated_packages (Optional[set]): A set of package names that have
            already been validated in the current run, to prevent cycles.
        depth (int): The current recursion depth for dependency scanning.
        deep_scan (bool): If True, recursively validate package dependencies.

    Returns:
        Dict[str, Any]: A dictionary containing the aggregated validation
        results, including errors, warnings, and detailed validator outputs.
    """
    logger.info(f"Validating package: {pkg_name}, version: {version}, depth: {depth}, deep_scan: {deep_scan}")
    validated_packages = validated_packages if validated_packages is not None else set()

    if pkg_name in validated_packages:
        return {}  # Avoid redundant or cyclical validation.

    max_depth = config.get("max_recursion_depth", 4)
    if deep_scan and depth > max_depth:
        logger.warning(f"Max recursion depth ({max_depth}) reached for {pkg_name}.")
        return {}

    validated_packages.add(pkg_name)

    # 1. Fetch metadata from PyPI.
    pypi_url = config.get("pypi_url", "https://pypi.org/pypi/")
    timeout = config.get("timeout", 30)
    try:
        url = f"{pypi_url}{pkg_name}/{version}/json" if version else f"{pypi_url}{pkg_name}/json"
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        metadata = response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to fetch metadata for '{pkg_name}': {e}") from e

    with tempfile.TemporaryDirectory() as temp_dir:
        # 2. Download and extract the package.
        dist_url = _get_dist_url(metadata, version=version)
        downloaded_file_path, extracted_path = (
            _download_and_extract_package(dist_url, temp_dir) if dist_url else (None, None)
        )

        # 3. Discover and instantiate all enabled validators.
        all_validators = discover_validators()
        enabled_validators = [
            v(pkg_name, metadata, config, extracted_path, downloaded_file_path)
            for v in all_validators
            if config.is_validator_enabled(v.name)
        ]

        # 4. Run validators concurrently for efficiency.
        with ThreadPoolExecutor(max_workers=10) as executor:
            validator_results = list(executor.map(lambda v: v.validate(), enabled_validators))

    # 5. Aggregate results and recursively validate dependencies if needed.
    aggregated_errors = [err for res in validator_results for err in res.get("errors", [])]
    aggregated_warnings = [warn for res in validator_results for warn in res.get("warnings", [])]

    dependency_results = []
    if deep_scan:
        dependencies = set()
        for res in validator_results:
            # Collect unique dependencies from all validators
            deps = res.get("info", {}).get("dependencies")
            if deps:
                dependencies.update(deps)

        for dep in sorted(list(dependencies)):
            try:
                dep_results = validate_package(dep, config, validated_packages=validated_packages, depth=depth + 1, deep_scan=True)
                if dep_results:
                    dependency_results.append(dep_results)
            except RuntimeError as e:
                logger.error(f"Could not validate dependency '{dep}' of '{pkg_name}': {e}")

    return {
        "package": pkg_name,
        "errors": aggregated_errors,
        "warnings": aggregated_warnings,
        "validator_results": validator_results,
        "dependencies": dependency_results,
    }