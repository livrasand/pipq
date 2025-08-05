"""
Utilities for interacting with PyPI API.
"""

import requests
from typing import Dict, Any, Optional
from urllib.parse import urljoin





def fetch_package_metadata(pkg_name: str, pypi_url: str = "https://pypi.org/pypi/") -> Dict[str, Any]:
    """
    Fetch package metadata from PyPI API.
    
    Args:
        pkg_name: Name of the package
        pypi_url: Base URL for PyPI API
        
    Returns:
        Dictionary containing package metadata
        
    Raises:
        requests.RequestException: If API request fails
        ValueError: If package not found
    """
    url = urljoin(pypi_url, f"{pkg_name}/json")
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        return response.json()
        
    except requests.exceptions.HTTPError as e:
        if response.status_code == 404:
            raise ValueError(f"Package '{pkg_name}' not found on PyPI")
        raise e
    except requests.exceptions.RequestException as e:
        raise e


def get_package_info(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract relevant package information from metadata.
    
    Args:
        metadata: Raw metadata from PyPI API
        
    Returns:
        Dictionary with extracted package information
    """
    info = metadata.get("info", {})
    
    return {
        "name": info.get("name", "Unknown"),
        "version": info.get("version", "Unknown"),
        "summary": info.get("summary", ""),
        "description": info.get("description", ""),
        "author": info.get("author", ""),
        "author_email": info.get("author_email", ""),
        "maintainer": info.get("maintainer", ""),
        "maintainer_email": info.get("maintainer_email", ""),
        "license": info.get("license", ""),
        "home_page": info.get("home_page", ""),
        "project_urls": info.get("project_urls", {}),
        "classifiers": info.get("classifiers", []),
        "keywords": info.get("keywords", ""),
        "requires_dist": info.get("requires_dist", []),
        "requires_python": info.get("requires_python", ""),
        "upload_time": info.get("upload_time", ""),
        "yanked": info.get("yanked", False),
        "yanked_reason": info.get("yanked_reason", ""),
    }


def get_release_info(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract release information from metadata.
    
    Args:
        metadata: Raw metadata from PyPI API
        
    Returns:
        Dictionary with release information
    """
    releases = metadata.get("releases", {})
    
    if not releases:
        return {
            "total_releases": 0,
            "latest_release": None,
            "first_release": None,
            "release_frequency": 0,
        }
    
    # Sort releases by version (this is a simplified sort)
    sorted_versions = sorted(releases.keys())
    
    return {
        "total_releases": len(releases),
        "latest_release": sorted_versions[-1] if sorted_versions else None,
        "first_release": sorted_versions[0] if sorted_versions else None,
        "all_versions": sorted_versions,
        "has_prerelease": any("a" in v or "b" in v or "rc" in v for v in sorted_versions),
    }


def check_package_exists(pkg_name: str, pypi_url: str = "https://pypi.org/pypi/") -> bool:
    """
    Check if a package exists on PyPI.
    
    Args:
        pkg_name: Name of the package
        pypi_url: Base URL for PyPI API
        
    Returns:
        True if package exists, False otherwise
    """
    try:
        fetch_package_metadata(pkg_name, pypi_url)
        return True
    except (ValueError, requests.RequestException):
        return False
