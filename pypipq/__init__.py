"""
pipq
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A secure pip proxy that analyzes packages before installation to detect
potential security issues, typosquatting, and other risks.
"""

__version__ = "0.1.0"
__author__ = "Livrädo Sandoval"
__email__ = "livrasand@outlook.com"
__license__ = "GPLv3"

from .core.validator import validate_package
from .core.config import Config

__all__ = ["validate_package", "Config", "__version__"]
