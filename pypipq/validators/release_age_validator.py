# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

"""
Release age validator for supply chain security.
"""

from datetime import datetime, timedelta
import re
from typing import Dict, Any, Optional, List
from ..core.base_validator import BaseValidator
from ..core.config import Config


class ReleaseAgeValidator(BaseValidator):
    """
    Validator that enforces minimum release age policies.
    """

    name = "ReleaseAge"
    category = "Supply Chain Security"
    description = "Enforces minimum release age to prevent supply chain attacks"

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        super().__init__(pkg_name, metadata, config, **kwargs)

        # Configuración por defecto
        self.default_min_age = self.config.get("security.minimum_release_age", 0)  # 0 = deshabilitado
        self.exclude_patterns = self.config.get("security.minimum_release_age_exclude", [])
        self.package_policies = self.config.get("security.package_policies", {})

    def _validate(self) -> None:
        """Valida la edad de la versión del paquete."""

        if self.default_min_age == 0:
            self.add_info("Release Age Check", "Disabled")
            return

        # Verificar si el paquete está excluido
        if self._is_package_excluded():
            self.add_info("Release Age Check", f"Excluded from age restrictions")
            return

        # Obtener la política específica para este paquete
        min_age_minutes = self._get_package_policy()

        if min_age_minutes == 0:
            self.add_info("Release Age Check", "No age restriction for this package")
            return

        # Obtener la fecha de publicación
        upload_time = self._get_upload_time()
        if not upload_time:
            self.add_warning("Cannot determine package release time")
            return

        try:
            release_time = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            self.add_warning("Cannot parse package release time")
            return

        # Calcular la edad
        now = datetime.now(release_time.tzinfo)
        age_minutes = (now - release_time).total_seconds() / 60

        required_age_hours = min_age_minutes / 60
        actual_age_hours = age_minutes / 60

        if age_minutes < min_age_minutes:
            self.add_error(
                f"Package version is too new! Released {actual_age_hours:.1f} hours ago, "
                f"but policy requires minimum {required_age_hours:.1f} hours. "
                f"This helps protect against supply chain attacks."
            )
        else:
            self.add_info("Release Age", f"OK ({actual_age_hours:.1f} hours old)")

    def _is_package_excluded(self) -> bool:
        """Verifica si el paquete está en la lista de exclusión."""
        pkg_name = self.pkg_name.lower()

        for pattern in self.exclude_patterns:
            # Soporte para patrones con asterisco
            if pattern.endswith('*'):
                if pkg_name.startswith(pattern[:-1].lower()):
                    return True
            elif pattern.startswith('@') and pattern.endswith('/*'):
                # Soporte para scoped packages: @myorg/*
                scope = pattern[1:-2].lower()
                if pkg_name.startswith(f"{scope}/"):
                    return True
            elif pkg_name == pattern.lower():
                return True

        return False

    def _get_package_policy(self) -> int:
        """Obtiene la política específica para este paquete."""
        pkg_name = self.pkg_name.lower()

        # Buscar políticas específicas
        for pattern, policy in self.package_policies.items():
            if self._matches_pattern(pkg_name, pattern):
                return policy.get("minimum_release_age", self.default_min_age)

        return self.default_min_age

    def _matches_pattern(self, pkg_name: str, pattern: str) -> bool:
        """Verifica si un paquete coincide con un patrón."""
        if pattern.endswith('*'):
            return pkg_name.startswith(pattern[:-1].lower())
        elif pattern.startswith('@') and pattern.endswith('/*'):
            scope = pattern[1:-2].lower()
            return pkg_name.startswith(f"{scope}/")
        else:
            return pkg_name == pattern.lower()

    def _get_upload_time(self) -> Optional[str]:
        """Obtiene la fecha de publicación de la versión actual."""
        version = self.get_metadata_field("version")
        if not version:
            return None

        releases = self.metadata.get("releases", {})
        version_files = releases.get(version, [])

        if not version_files:
            return None

        # Tomar la fecha del primer archivo de esta versión
        return version_files[0].get("upload_time_iso_8601")