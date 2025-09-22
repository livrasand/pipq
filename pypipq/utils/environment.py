# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

"""
Utilities for interacting with the local Python environment.
"""
import os
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple

def get_installed_packages() -> List[Dict[str, str]]:
    """
    Get a list of all installed packages in the current environment.

    Returns:
        A list of dictionaries, where each dictionary represents a package
        with 'name' and 'version' keys.
    """
    try:
        # Using --format=json is more reliable than parsing 'pip freeze'
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: Could not list installed packages: {e}")
        return []

def detect_dependency_file() -> Optional[str]:
    """
    Detects the presence of dependency files in a specific order.

    Returns:
        The path to the first dependency file found, or None.
    """
    # Order of priority
    dependency_files = [
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "Pipfile" # Lower priority but good to have
    ]
    for file_name in dependency_files:
        if Path(file_name).exists():
            return file_name
    return None

def parse_dependencies(file_path: str, include_dev: bool = False) -> List[str]:
    """
    Parses a dependency file and returns a list of requirements.

    Args:
        file_path: The path to the dependency file.
        include_dev: Whether to include development dependencies.

    Returns:
        A list of package specifiers.
    """
    if file_path.endswith("requirements.txt"):
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]

    elif file_path.endswith("pyproject.toml"):
        try:
            import tomli
        except ImportError:
            print("Warning: 'tomli' is required to parse pyproject.toml. Please install it.")
            return []

        with open(file_path, "rb") as f:
            data = tomli.load(f)

        deps = data.get("project", {}).get("dependencies", [])

        if include_dev:
            optional_deps = data.get("project", {}).get("optional-dependencies", {})
            # A common convention for dev dependencies
            dev_deps = optional_deps.get("dev", [])
            deps.extend(dev_deps)
            # Also check tool-specific sections like poetry or pdm
            if "tool" in data:
                if "poetry" in data["tool"]:
                    deps.extend(data["tool"]["poetry"].get("dev-dependencies", {}).keys())
                if "pdm" in data["tool"]:
                    deps.extend(data["tool"]["pdm"].get("dev-dependencies", {}).get("dev", []))

        return deps

    elif file_path.endswith("setup.py"):
        # This is a very basic parser. A proper one would need to execute the file,
        # which is a security risk. We'll just do a best-effort string search.
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            # Look for install_requires=[...]
            import re
            match = re.search(r"install_requires\s*=\s*\[([^\]]*)\]", content)
            if match:
                return [req.strip().strip("'\"") for req in match.group(1).split(',') if req.strip()]
        except Exception:
            return [] # Ignore parsing errors for setup.py

    elif file_path.endswith("Pipfile"):
        try:
            import tomli
        except ImportError:
            print("Warning: 'tomli' is required to parse Pipfile. Please install it.")
            return []

        with open(file_path, "rb") as f:
            data = tomli.load(f)

        deps = list(data.get("packages", {}).keys())
        if include_dev:
            deps.extend(list(data.get("dev-packages", {}).keys()))
        return deps

    return []
