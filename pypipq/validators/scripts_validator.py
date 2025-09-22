from ..core.base_validator import BaseValidator
from ..core.config import Config
from typing import Dict, Any, List
import os
import re
from pathlib import Path

class ScriptsValidator(BaseValidator):
    """
    Validator that detects pre/post install scripts.
    """
    name = "Install Scripts"
    category = "Security"
    description = "Detects pre/post install scripts."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)

    def _validate(self) -> None:
        """Check for install scripts in the package."""
        scripts_found = []

        # Check metadata for entry points (console scripts)
        entry_points = self._check_entry_points()
        if entry_points:
            scripts_found.extend([f"Entry point: {ep}" for ep in entry_points])

        # Check extracted files for script files
        if self.extracted_path:
            file_scripts = self._check_extracted_scripts()
            if file_scripts:
                scripts_found.extend([f"Script file: {script}" for script in file_scripts])

        # Check for setup.py scripts
        setup_scripts = self._check_setup_scripts()
        if setup_scripts:
            scripts_found.extend([f"Setup script: {script}" for script in setup_scripts])

        if scripts_found:
            for script in scripts_found:
                self.add_warning(f"Install script detected: {script}")
        else:
            self.add_info("Install Script Check", "No install scripts detected.")

    def _check_entry_points(self) -> List[str]:
        """Check for console scripts in entry points."""
        scripts = []

        # Check in metadata info
        info = self.metadata.get("info", {})
        project_urls = info.get("project_urls", {})

        # PyPI metadata may include entry points in various formats
        # Check for common entry point indicators
        entry_points = info.get("entry_points", {})
        if entry_points:
            if isinstance(entry_points, dict):
                for group, entries in entry_points.items():
                    if group == "console_scripts" or "script" in group.lower():
                        if isinstance(entries, list):
                            scripts.extend(entries)
                        elif isinstance(entries, dict):
                            scripts.extend(entries.keys())

        # Also check for scripts in classifiers or other metadata
        classifiers = info.get("classifiers", [])
        for classifier in classifiers:
            if "script" in classifier.lower():
                scripts.append(f"Classifier indicates scripts: {classifier}")

        return scripts

    def _check_extracted_scripts(self) -> List[str]:
        """Check extracted package files for script files."""
        scripts = []

        if not self.extracted_path or not os.path.exists(self.extracted_path):
            return scripts

        script_patterns = [
            r'^#!.*python',  # Shebang lines
            r'^#!/.*',       # Any shebang
        ]

        # Common script directories and files
        script_files = [
            'setup.py',
            'pyproject.toml',
            'MANIFEST.in',
            'Makefile',
            'build.sh',
            'install.sh',
            'postinstall.py',
            'preinstall.py',
        ]

        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.extracted_path)

                # Check if it's a known script file
                if file in script_files:
                    scripts.append(rel_path)
                    continue

                # Check file extension
                if file.endswith(('.sh', '.bat', '.cmd', '.ps1', '.py')):
                    scripts.append(rel_path)
                    continue

                # Check for shebang in first line
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        first_line = f.readline().strip()
                        for pattern in script_patterns:
                            if re.search(pattern, first_line):
                                scripts.append(rel_path)
                                break
                except (OSError, UnicodeDecodeError):
                    # If we can't read it as text, it might be binary
                    pass

        return scripts

    def _check_setup_scripts(self) -> List[str]:
        """Check setup.py for script definitions."""
        scripts = []

        if not self.extracted_path:
            return scripts

        setup_py_path = os.path.join(self.extracted_path, 'setup.py')
        if not os.path.exists(setup_py_path):
            return scripts

        try:
            with open(setup_py_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Look for scripts parameter in setup() call
                scripts_match = re.search(r'scripts\s*=\s*(\[.*?\])', content, re.DOTALL)
                if scripts_match:
                    scripts.append("setup.py contains scripts parameter")

                # Look for entry_points with console_scripts
                entry_points_match = re.search(r'entry_points\s*=\s*(\{.*?\})', content, re.DOTALL)
                if entry_points_match:
                    entry_points_str = entry_points_match.group(1)
                    if 'console_scripts' in entry_points_str:
                        scripts.append("setup.py contains console_scripts entry points")

                # Look for other script-related patterns
                if re.search(r'cmdclass|Command', content):
                    scripts.append("setup.py contains custom commands")

        except (OSError, UnicodeDecodeError):
            pass

        return scripts
