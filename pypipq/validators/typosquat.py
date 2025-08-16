"""
Typosquatting detection validator.

Detects packages with names similar to popular packages that might be
attempting to masquerade as legitimate packages.
"""

import difflib
import re
from typing import Dict, Any, List, Optional
from ..core.base_validator import BaseValidator
from ..core.config import Config

class TyposquatValidator(BaseValidator):
    """
    Validator that detects potential typosquatting attempts.
    
    This validator checks if the package name is suspiciously similar to
    well-known, popular packages that attackers commonly target.
    """
    
    name = "Typosquat"
    category = "Security"
    description = "Detects packages with names similar to popular packages"
    
    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, extracted_path: Optional[str] = None, downloaded_file_path: Optional[str] = None) -> None:
        super().__init__(pkg_name, metadata, config, extracted_path=extracted_path, downloaded_file_path=downloaded_file_path)
        self.popular_packages = self.config.get("validators.Typosquat.popular_packages", {
            "requests", "urllib3", "setuptools", "certifi", "numpy", "pandas",
            "matplotlib", "scipy", "pillow", "cryptography", "pytz", "six",
            "python-dateutil", "pyyaml", "click", "jinja2", "markupsafe",
            "werkzeug", "flask", "django", "sqlalchemy", "psycopg2", "pymongo",
            "redis", "boto3", "botocore", "awscli", "docker", "kubernetes",
            "tensorflow", "torch", "scikit-learn", "beautifulsoup4", "lxml",
            "selenium", "pytest", "coverage", "tox", "black", "flake8", "mypy",
            "isort", "pre-commit", "pipenv", "poetry", "wheel", "twine",
        })
        self.whitelist = self.config.get("validators.Typosquat.whitelist", [
            # Legitimate packages that are often flagged as typosquats
            r"django-.*",
            r"flask-.*",
            r"pytest-.*",
        ])

    def _validate(self) -> None:
        """Check for potential typosquatting."""
        pkg_name = self.pkg_name.lower()
        
        # Skip validation for packages that are actually popular
        if pkg_name in self.popular_packages:
            return

        # Skip validation for whitelisted packages
        for pattern in self.whitelist:
            if re.fullmatch(pattern, pkg_name):
                self.add_info("Typosquat Check", f"'{pkg_name}' is whitelisted.")
                return
        
        suspicious_matches = []
        
        for popular_pkg in self.popular_packages:
            similarity = self._calculate_similarity(pkg_name, popular_pkg)
            
            # Check for high similarity (potential typosquatting)
            if 0.6 <= similarity < 1.0:  # 60-99% similar
                suspicious_matches.append({
                    "target": popular_pkg,
                    "similarity": similarity,
                    "distance": self._levenshtein_distance(pkg_name, popular_pkg)
                })
        
        # Sort by similarity (highest first)
        suspicious_matches.sort(key=lambda x: x["similarity"], reverse=True)
        
        # Report findings
        if suspicious_matches:
            top_match = suspicious_matches[0]
            
            if top_match["similarity"] >= 0.85:  # Very high similarity
                self.add_error(
                    f"Package name '{self.pkg_name}' is very similar to popular package "
                    f"'{top_match['target']}' ({top_match['similarity']:.0%} similarity). "
                    f"This could be a typosquatting attempt."
                )
            elif top_match["similarity"] >= 0.75:  # High similarity
                self.add_warning(
                    f"Package name '{self.pkg_name}' is similar to popular package "
                    f"'{top_match['target']}' ({top_match['similarity']:.0%} similarity). "
                    f"Please verify this is the intended package."
                )
            
            # Add info about all suspicious matches
            self.add_info("suspicious_matches", suspicious_matches[:3])  # Top 3 matches
    
    def _calculate_similarity(self, name1: str, name2: str) -> float:
        """
        Calculate similarity between two package names.
        
        Uses difflib.SequenceMatcher to get a similarity ratio.
        """
        return difflib.SequenceMatcher(None, name1, name2).ratio()
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein distance between two strings.
        
        Returns the minimum number of single-character edits required
        to change one string into another.
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, char1 in enumerate(s1):
            current_row = [i + 1]
            for j, char2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (char1 != char2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
