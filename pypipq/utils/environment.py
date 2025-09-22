"""Provides utilities for interacting with the local Python environment.

This module includes functions for discovering installed packages and for
detecting and parsing various types of dependency definition files, such as
`requirements.txt` and `pyproject.toml`.
"""
import sys
import json
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Optional

# Conditional import of tomli for TOML parsing.
try:
    import tomli
except ImportError:
    tomli = None


def get_installed_packages() -> List[Dict[str, str]]:
    """Retrieves a list of all installed packages in the current environment.

    This function uses the `pip list --format=json` command, which provides a
    more reliable and easily parsable output than `pip freeze`.

    Returns:
        List[Dict[str, str]]: A list of dictionaries, where each dictionary
        represents an installed package and contains "name" and "version"
        keys. Returns an empty list if the command fails.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: Could not list installed packages via pip: {e}", file=sys.stderr)
        return []


def detect_dependency_file() -> Optional[str]:
    """Detects the presence of common dependency files in the current directory.

    It searches for files in a predefined order of priority: `pyproject.toml`,
    `requirements.txt`, `setup.py`, and `Pipfile`.

    Returns:
        Optional[str]: The filename of the first dependency file found, or
        None if no recognized file is present.
    """
    dependency_files = [
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "Pipfile",
    ]
    for file_name in dependency_files:
        if Path(file_name).exists():
            return file_name
    return None


def parse_dependencies(file_path: str, include_dev: bool = False) -> List[str]:
    """Parses a dependency file and returns a list of package specifiers.

    This function supports `requirements.txt`, `pyproject.toml`, `setup.py`,
    and `Pipfile`. The parsing for `setup.py` is a best-effort attempt using
    regular expressions to avoid executing the file.

    Args:
        file_path (str): The path to the dependency file.
        include_dev (bool): If True, includes development dependencies from
            `pyproject.toml` and `Pipfile`.

    Returns:
        List[str]: A list of package requirement strings (e.g., "requests>=2.0").
    """
    filename = Path(file_path).name

    if filename == "requirements.txt":
        return _parse_requirements_txt(file_path)
    elif filename == "pyproject.toml":
        return _parse_pyproject_toml(file_path, include_dev)
    elif filename == "setup.py":
        return _parse_setup_py(file_path)
    elif filename == "Pipfile":
        return _parse_pipfile(file_path, include_dev)
    return []


def _parse_requirements_txt(file_path: str) -> List[str]:
    """Parses a requirements.txt file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except IOError as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)
        return []


def _parse_pyproject_toml(file_path: str, include_dev: bool) -> List[str]:
    """Parses a pyproject.toml file."""
    if not tomli:
        print("Warning: 'tomli' is required to parse pyproject.toml. Please install it.", file=sys.stderr)
        return []

    try:
        with open(file_path, "rb") as f:
            data = tomli.load(f)
    except (IOError, tomli.TOMLDecodeError) as e:
        print(f"Warning: Could not parse {file_path}: {e}", file=sys.stderr)
        return []

    deps = data.get("project", {}).get("dependencies", [])
    if include_dev:
        optional_deps = data.get("project", {}).get("optional-dependencies", {})
        dev_deps = optional_deps.get("dev", [])
        deps.extend(dev_deps)

        # Also check for common tool-specific dev dependencies.
        if "tool" in data:
            if "poetry" in data["tool"]:
                poetry_dev_deps = data["tool"]["poetry"].get("dev-dependencies", {})
                deps.extend(poetry_dev_deps.keys())
            if "pdm" in data["tool"]:
                pdm_dev_deps = data["tool"]["pdm"].get("dev-dependencies", {}).get("dev", [])
                deps.extend(pdm_dev_deps)
    return deps


def _parse_setup_py(file_path: str) -> List[str]:
    """Performs a best-effort parse of a setup.py file using regex."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        match = re.search(r"install_requires\s*=\s*\[([^\]]*)\]", content)
        if match:
            # This is a simple split and may not handle all edge cases.
            return [req.strip().strip("'\"") for req in match.group(1).split(',') if req.strip()]
    except (IOError, re.error) as e:
        print(f"Warning: Could not parse {file_path}: {e}", file=sys.stderr)
    return []


def _parse_pipfile(file_path: str, include_dev: bool) -> List[str]:
    """Parses a Pipfile."""
    if not tomli:
        print("Warning: 'tomli' is required to parse Pipfile. Please install it.", file=sys.stderr)
        return []

    try:
        with open(file_path, "rb") as f:
            data = tomli.load(f)
    except (IOError, tomli.TOMLDecodeError) as e:
        print(f"Warning: Could not parse {file_path}: {e}", file=sys.stderr)
        return []

    # Pipfiles store dependencies as key-value pairs.
    deps = list(data.get("packages", {}).keys())
    if include_dev:
        deps.extend(list(data.get("dev-packages", {}).keys()))
    return deps
