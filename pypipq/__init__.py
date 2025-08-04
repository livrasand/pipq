"""
pypipq - A secure pip proxy inspired by npq
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A secure pip proxy that analyzes packages before installation to detect
potential security issues, typosquatting, and other risks.

:copyright: (c) 2024 by pypipq contributors.
:license: MIT, see LICENSE for more details.
"""

__version__ = "0.1.0"
__author__ = "pypipq contributors"
__email__ = "your.email@example.com"
__license__ = "MIT"

from .core.validator import validate_package
from .core.config import Config

__all__ = ["validate_package", "Config", "__version__"]
