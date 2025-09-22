"""Provides utility functions for interacting with the PyPI JSON API.

This module simplifies the process of fetching and parsing package metadata
from the Python Package Index, handling API requests, retries, and error
conditions.
"""

import requests
import logging
import time
from typing import Dict, Any
from urllib.parse import urljoin

# Initialize a logger for this module.
logger = logging.getLogger(__name__)


def fetch_package_metadata(pkg_name: str, pypi_url: str = "https://pypi.org/pypi/", retries: int = 3) -> Dict[str, Any]:
    """Fetches the full JSON metadata for a package from the PyPI API.

    This function includes a retry mechanism with exponential backoff to handle
    transient network issues or API rate limiting.

    Args:
        pkg_name (str): The name of the package to fetch.
        pypi_url (str): The base URL of the PyPI-compatible repository.
            Defaults to "https://pypi.org/pypi/".
        retries (int): The number of times to retry the request on failure.
            Defaults to 3.

    Returns:
        Dict[str, Any]: A dictionary containing the complete package metadata.

    Raises:
        ValueError: If the package is not found (HTTP 404).
        requests.RequestException: If the request fails after all retries
            due to a non-404 HTTP error or a network issue.
    """
    logger.info(f"Fetching metadata for package: {pkg_name} from {pypi_url}")
    url = urljoin(pypi_url, f"{pkg_name}/json")

    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 429:  # Handle rate limiting
                sleep_time = 2 ** attempt
                logger.warning(f"Rate limited. Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
                continue
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise ValueError(f"Package '{pkg_name}' not found on PyPI.") from e
            if attempt == retries - 1:
                raise
        except requests.exceptions.RequestException as e:
            if attempt == retries - 1:
                raise
    # This part should be unreachable if retries > 0, but is here for completeness.
    raise requests.exceptions.RequestException("Failed to fetch metadata after all retries.")


def get_package_info(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts a curated set of package information from the raw metadata.

    This function provides a simplified and consistent view of the most
    commonly used fields from the 'info' section of the PyPI metadata.

    Args:
        metadata (Dict[str, Any]): The raw metadata dictionary from the PyPI API.

    Returns:
        Dict[str, Any]: A dictionary containing key package details.
    """
    info = metadata.get("info", {})
    return {
        "name": info.get("name"),
        "version": info.get("version"),
        "summary": info.get("summary"),
        "description": info.get("description"),
        "author": info.get("author"),
        "author_email": info.get("author_email"),
        "maintainer": info.get("maintainer"),
        "maintainer_email": info.get("maintainer_email"),
        "license": info.get("license"),
        "home_page": info.get("home_page"),
        "project_urls": info.get("project_urls", {}),
        "classifiers": info.get("classifiers", []),
        "keywords": info.get("keywords"),
        "requires_dist": info.get("requires_dist", []),
        "requires_python": info.get("requires_python"),
        "upload_time": info.get("upload_time"),
        "yanked": info.get("yanked", False),
        "yanked_reason": info.get("yanked_reason"),
    }


def get_release_info(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts and summarizes release history from the package metadata.

    Note: The version sorting is lexicographical and may not be perfectly
    accurate for all versioning schemes (e.g., PEP 440).

    Args:
        metadata (Dict[str, Any]): The raw metadata dictionary from the PyPI API.

    Returns:
        Dict[str, Any]: A dictionary summarizing the release history.
    """
    releases = metadata.get("releases", {})
    if not releases:
        return {
            "total_releases": 0,
            "latest_release": None,
            "first_release": None,
            "all_versions": [],
            "has_prerelease": False,
        }

    # A simple lexicographical sort. For true PEP 440 sorting, a library
    # like 'packaging' would be needed.
    sorted_versions = sorted(releases.keys())
    has_prerelease = any("a" in v or "b" in v or "rc" in v for v in sorted_versions)

    return {
        "total_releases": len(releases),
        "latest_release": sorted_versions[-1] if sorted_versions else None,
        "first_release": sorted_versions[0] if sorted_versions else None,
        "all_versions": sorted_versions,
        "has_prerelease": has_prerelease,
    }


def check_package_exists(pkg_name: str, pypi_url: str = "https://pypi.org/pypi/") -> bool:
    """Checks if a package exists on PyPI without fetching the full metadata.

    Args:
        pkg_name (str): The name of the package to check.
        pypi_url (str): The base URL of the PyPI-compatible repository.
            Defaults to "https://pypi.org/pypi/".

    Returns:
        bool: True if the package exists, False otherwise.
    """
    try:
        # We only need the head to check for existence, which is faster.
        url = urljoin(pypi_url, f"{pkg_name}/json")
        response = requests.head(url, timeout=10)
        return response.status_code == 200
    except requests.RequestException:
        return False
