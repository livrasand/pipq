"""Analyzes package dependencies for potential security and quality issues.

This validator inspects a package's dependencies to identify risks such as:
-   An excessive number of dependencies, which can increase the attack surface.
-   Circular dependencies, which can indicate design problems or cause
    resolution issues.
-   A simplified supply chain risk score based on the number and depth of
    dependencies.
"""
import re
from typing import Dict, Any, List, Set

from ..core.base_validator import BaseValidator
from ..core.config import Config
from ..utils.pypi import fetch_package_metadata


class DependencyValidator(BaseValidator):
    """Analyzes package dependencies for potential issues."""

    name = "Dependency"
    category = "Risk"
    description = "Analyzes package dependencies for potential security issues."

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the DependencyValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        self.max_deps_threshold = self.config.get("validators.Dependency.max_deps_threshold", 20)
        self.max_depth = self.config.get("validators.Dependency.max_depth", 5)

    def _validate(self) -> None:
        """Performs the dependency analysis."""
        dependencies = self._extract_dependencies()
        if len(dependencies) > self.max_deps_threshold:
            self.add_warning(
                f"Package has a large number of direct dependencies ({len(dependencies)}), "
                "which could increase the attack surface."
            )
        self.add_info("dependencies", dependencies)

        # Perform a deeper, recursive analysis of the dependency tree.
        deps_tree = self._build_dependency_tree(max_depth=self.max_depth)
        if not deps_tree:
            return

        if self._has_circular_deps(deps_tree):
            self.add_error("Circular dependencies were detected in the dependency graph.")

        risk_score = self._calculate_supply_chain_risk(deps_tree)
        self.add_info("supply_chain_risk_score", f"{risk_score:.2f}")
        if risk_score > 0.7:
            self.add_warning(f"Calculated supply chain risk is high ({risk_score:.2f}).")

    def _extract_dependencies(self) -> List[str]:
        """Extracts and cleans dependency names from metadata."""
        requires_dist = self.get_metadata_field('requires_dist', [])
        if not requires_dist:
            return []
        # Use regex to extract only the package name, removing version specifiers,
        # environment markers, and extras.
        return sorted(list(set(
            p for p in (re.split(r"[<>=!~;[\] ]", d)[0].strip() for d in requires_dist) if p
        )))

    def _build_dependency_tree(self, max_depth: int) -> Dict[str, List[str]]:
        """Recursively builds a dependency tree up to a specified depth.

        Args:
            max_depth (int): The maximum recursion depth.

        Returns:
            Dict[str, List[str]]: A dictionary representing the dependency tree.
        """
        tree: Dict[str, List[str]] = {}
        visited: Set[str] = set()

        def _build(pkg: str, depth: int):
            if depth >= max_depth or pkg in visited:
                return
            visited.add(pkg)

            try:
                # Fetch metadata for the dependency.
                # Note: This makes the validator network-intensive.
                meta = fetch_package_metadata(pkg)
                requires = meta.get("info", {}).get("requires_dist", [])
                deps = []
                if requires:
                    deps = sorted(list(set(
                        p for p in (re.split(r"[<>=!~;[\] ]", d)[0].strip() for d in requires) if p
                    )))
                tree[pkg] = deps
                for dep in deps:
                    _build(dep, depth + 1)
            except (ValueError, RuntimeError):
                # Could not fetch metadata for the dependency.
                tree[pkg] = []

        _build(self.pkg_name, 0)
        return tree

    def _has_circular_deps(self, deps_tree: Dict[str, List[str]]) -> bool:
        """Detects circular dependencies in the constructed tree using DFS.

        Args:
            deps_tree (Dict[str, List[str]]): The dependency tree.

        Returns:
            bool: True if a cycle is detected, False otherwise.
        """
        visiting: Set[str] = set()  # Nodes currently in the recursion stack.
        visited: Set[str] = set()   # All nodes that have been visited.

        def _has_cycle(pkg: str) -> bool:
            visiting.add(pkg)
            visited.add(pkg)

            for dep in deps_tree.get(pkg, []):
                if dep not in visited:
                    if _has_cycle(dep):
                        return True
                elif dep in visiting:
                    return True  # A back edge indicates a cycle.

            visiting.remove(pkg)
            return False

        for pkg in deps_tree:
            if pkg not in visited:
                if _has_cycle(pkg):
                    return True
        return False

    def _calculate_supply_chain_risk(self, deps_tree: Dict[str, List[str]]) -> float:
        """Calculates a simplified risk score for the supply chain.

        This is a heuristic-based calculation. A more advanced implementation
        would consider package popularity, maintainer reputation, vulnerability
        data, etc.

        Args:
            deps_tree (Dict[str, List[str]]): The dependency tree.

        Returns:
            float: A risk score between 0.0 and 1.0.
        """
        total_deps = len(deps_tree)
        if total_deps == 0:
            return 0.0

        # Risk increases with the number of total dependencies.
        risk = min(total_deps / 50.0, 1.0)

        # Risk also increases with the depth of the dependency chain.
        if deps_tree:
            max_transitive = max(len(deps) for deps in deps_tree.values())
            risk += min(max_transitive / 20.0, 0.5)

        return min(risk, 1.0)
