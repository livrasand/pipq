# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

from ..core.base_validator import BaseValidator
from ..core.config import Config
from ..utils.pypi import fetch_package_metadata
from typing import Dict, Any, List, Set, Tuple
import re

class DependencyValidator(BaseValidator):
    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config)
        self.name = "Dependency Validator"
        self.description = "Analyzes package dependencies for potential security issues."
        self.category = "Risk"

    def _validate(self) -> None:
        requires_dist = self.get_metadata_field('requires_dist')
        dependencies = []
        if requires_dist:
            # Use regex to extract only the package name, removing version specifiers, semicolons, and extras
            dependencies = [p for p in (re.split(r"[<>=!~;[\] ]", d)[0] for d in requires_dist) if p]
            if len(dependencies) > 20: # Arbitrary threshold for now
                self.add_warning(f"Package has a large number of dependencies ({len(dependencies)}). This could increase the attack surface.")

        self.add_info("dependencies", dependencies)

        # Recursive dependency analysis
        deps_tree = self._build_dependency_tree(max_depth=5)

        # Detect circular dependencies
        if self._has_circular_deps(deps_tree):
            self.add_warning("Circular dependencies detected (may be false positive)")

        # Analyze supply chain risk
        risk_score = self._calculate_supply_chain_risk(deps_tree)
        if risk_score > 0.7:
            self.add_warning(f"High supply chain risk: {risk_score:.2f}")

    def _build_dependency_tree(self, max_depth: int = 5) -> Dict[str, List[str]]:
        """Build a dependency tree recursively."""
        tree = {}
        visited = set()

        def _build(pkg: str, depth: int) -> List[str]:
            if depth >= max_depth or pkg in visited:
                return []
            visited.add(pkg)

            try:
                metadata = fetch_package_metadata(pkg)
                requires_dist = metadata.get("info", {}).get("requires_dist", [])
                deps = []
                if requires_dist:
                    deps = [re.split(r"[<>=!~;[\] ]", d)[0] for d in requires_dist if re.split(r"[<>=!~;[\] ]", d)[0]]

                tree[pkg] = deps
                for dep in deps:
                    _build(dep, depth + 1)
                return deps
            except Exception:
                return []

        _build(self.pkg_name, 0)
        return tree

    def _has_circular_deps(self, deps_tree: Dict[str, List[str]]) -> bool:
        """Detect circular dependencies in the dependency tree."""
        def _has_cycle(pkg: str, visited: Set[str], rec_stack: Set[str]) -> bool:
            visited.add(pkg)
            rec_stack.add(pkg)

            for dep in deps_tree.get(pkg, []):
                if dep not in visited:
                    if _has_cycle(dep, visited, rec_stack):
                        return True
                elif dep in rec_stack:
                    return True

            rec_stack.remove(pkg)
            return False

        visited = set()
        rec_stack = set()
        for pkg in deps_tree:
            if pkg not in visited:
                if _has_cycle(pkg, visited, rec_stack):
                    return True
        return False

    def _calculate_supply_chain_risk(self, deps_tree: Dict[str, List[str]]) -> float:
        """Calculate supply chain risk score."""
        total_deps = len(deps_tree)
        if total_deps == 0:
            return 0.0

        # Simple risk calculation based on number of dependencies
        # In a real implementation, this would consider maintainer reputation, etc.
        risk = min(total_deps / 50.0, 1.0)  # Cap at 1.0

        # Add risk for packages with many transitive dependencies
        max_transitive = max(len(deps) for deps in deps_tree.values()) if deps_tree else 0
        risk += min(max_transitive / 20.0, 0.5)

        return min(risk, 1.0)
