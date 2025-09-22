"""Detects packages with names similar to popular packages.

Typosquatting is a common attack vector where a malicious package is named
very similarly to a popular, legitimate one (e.g., `python-dateutil` vs.
`python-datetutil`) to trick users into installing it. This validator
compares the package name against a configurable list of popular packages
to identify such attempts.
"""
import difflib
import re
from typing import Dict, Any, Optional

from ..core.base_validator import BaseValidator
from ..core.config import Config


class TyposquatValidator(BaseValidator):
    """Detects potential typosquatting attempts by checking for name similarity.

    This validator compares the package name against a list of well-known,
    popular packages using string similarity and distance algorithms. It also
    maintains a whitelist for legitimate packages that might otherwise be
    flagged (e.g., `pytest-django`).
    """

    name = "Typosquat"
    category = "Security"
    description = "Detects packages with names deceptively similar to popular ones."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the TyposquatValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        self.popular_packages = self.config.get("validators.Typosquat.popular_packages", [
            "requests", "urllib3", "setuptools", "certifi", "numpy", "pandas",
            "matplotlib", "scipy", "pillow", "cryptography", "pytz", "six",
            "python-dateutil", "pyyaml", "click", "jinja2", "markupsafe",
            "werkzeug", "flask", "django", "sqlalchemy", "psycopg2", "pymongo",
            "redis", "boto3", "botocore", "awscli", "docker", "kubernetes",
            "tensorflow", "torch", "scikit-learn", "beautifulsoup4", "lxml",
            "selenium", "pytest", "coverage", "tox", "black", "flake8", "mypy",
            "isort", "pre-commit", "pipenv", "poetry", "wheel", "twine",
        ])
        self.whitelist_patterns = self.config.get("validators.Typosquat.whitelist", [
            r"django-.*", r"flask-.*", r"pytest-.*",
        ])

    def _validate(self) -> None:
        """Performs the typosquatting check."""
        pkg_name_lower = self.pkg_name.lower()

        if pkg_name_lower in self.popular_packages:
            return  # The package is a known popular package.

        for pattern in self.whitelist_patterns:
            if re.fullmatch(pattern, pkg_name_lower):
                self.add_info("Typosquat Check", f"'{self.pkg_name}' is whitelisted and skipped.")
                return

        suspicious_matches = []
        for popular_pkg in self.popular_packages:
            similarity = difflib.SequenceMatcher(None, pkg_name_lower, popular_pkg).ratio()
            if 0.6 <= similarity < 1.0:  # Find names that are 60-99% similar.
                suspicious_matches.append({
                    "target": popular_pkg,
                    "similarity": similarity,
                    "distance": self._damerau_levenshtein(pkg_name_lower, popular_pkg),
                })

        if not suspicious_matches:
            return

        # Sort by highest similarity and report the top match.
        suspicious_matches.sort(key=lambda x: x["similarity"], reverse=True)
        top_match = suspicious_matches[0]

        if top_match["similarity"] >= 0.85:
            self.add_error(
                f"Package name '{self.pkg_name}' is very similar to the popular package "
                f"'{top_match['target']}' ({top_match['similarity']:.0%} similarity). "
                "This could be a typosquatting attempt."
            )
        elif top_match["similarity"] >= 0.75:
            self.add_warning(
                f"Package name '{self.pkg_name}' is similar to the popular package "
                f"'{top_match['target']}' ({top_match['similarity']:.0%} similarity). "
                "Please verify that this is the intended package."
            )

        self.add_info("Top Typosquat Matches", suspicious_matches[:3])

    def _damerau_levenshtein(self, s1: str, s2: str) -> int:
        """Calculates the Damerau-Levenshtein distance between two strings.

        This distance metric is an extension of Levenshtein distance that also
        considers the transposition of two adjacent characters as a single edit.

        Args:
            s1 (str): The first string.
            s2 (str): The second string.

        Returns:
            int: The Damerau-Levenshtein distance.
        """
        len1, len2 = len(s1), len(s2)
        d = {}
        for i in range(-1, len1 + 1):
            d[(i, -1)] = i + 1
        for j in range(-1, len2 + 1):
            d[(-1, j)] = j + 1

        for i in range(len1):
            for j in range(len2):
                cost = 0 if s1[i] == s2[j] else 1
                d[(i, j)] = min(
                    d[(i - 1, j)] + 1,       # Deletion
                    d[(i, j - 1)] + 1,       # Insertion
                    d[(i - 1, j - 1)] + cost, # Substitution
                )
                if i and j and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                    d[(i, j)] = min(d[(i, j)], d[i - 2, j - 2] + cost) # Transposition

        return d[len1 - 1, len2 - 1]
