# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

"""
Validators for pypipq.
Each validator should inherit from BaseValidator.
"""
from .age import AgeValidator
from .cryptographic_validator import CryptographicValidator
from .dependency_validator import DependencyValidator
from .expired_domains_validator import ExpiredDomainsValidator
from .gpg_validator import GPGValidator
from .integrity_validator import IntegrityValidator
from .license_validator import LicenseValidator
from .maintainer import MaintainerValidator
from .malware_detector import MalwareDetector
from .new_bin_validator import NewBinValidator
from .popularity_validator import PopularityValidator
from .provenance_validator import ProvenanceValidator
from .release_age_validator import ReleaseAgeValidator
from .static_analysis_validator import StaticAnalysisValidator
from .scripts_validator import ScriptsValidator
from .signatures_validator import SignaturesValidator
from .size_validator import SizeValidator
from .source_validator import SourceValidator
from .typosquat import TyposquatValidator
from .vulnerability_validator import VulnerabilityValidator
