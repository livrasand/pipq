# pipq

A secure pip proxy that analyzes Python packages before installation to detect potential security issues and risks.

![PyPI](https://img.shields.io/pypi/v/pypipq) [![PyPI Downloads](https://static.pepy.tech/badge/pypipq)](https://pepy.tech/projects/pypipq) 

## Overview

pipq is a command-line tool that acts as a security layer between you and pip. It intercepts package installation requests, analyzes packages for potential security threats, and provides warnings or blocks installation based on configurable security policies.

## Key Functionality

- **Zero‑setup installation** – a single (or ) gets you started `pip install pypipq`

### Package Analysis
- **Typosquatting Detection**: Identifies packages with names similar to popular packages that might be masquerading as legitimate libraries
- **Package Age Validation**: Flags packages that are suspiciously new (potential supply chain attacks) or very old without updates (potential abandonment)
- **Maintainer Analysis**: Detects packages maintained by a single individual, indicating higher risk of abandonment

### User Experience
- Rich terminal interface with colored output and progress indicators
- Interactive prompts for security decisions
- Multiple operation modes: silent, warn, or block
- Comprehensive configuration system via TOML files and environment variables

### Installation Workflow
```bash
pipq install requests           # Analyze and install if safe
pipq check suspicious-package   # Analyze without installing
pipq install --force package    # Skip analysis entirely
```

## Installation

```bash
pip install pypipq
```

## Usage

Replace `pip install` with `pipq install`:

```bash
# Basic usage
pipq install numpy pandas

# Check package without installing
pipq check potentially-malicious-package

# Force installation (skip validation)
pipq install --force some-package

# Silent mode (no prompts)
pipq install --silent package-name
```

## Configuration

Create `~/.config/pipq/config.toml`:

```toml
mode = "warn"                    # silent, warn, or block
auto_continue_warnings = true
disable_validators = []
timeout = 30
```

Or use environment variables:
```bash
export PIPQ_MODE=block
export PIPQ_DISABLE_VALIDATORS=age,maintainer
```

## Architecture

pipq uses a modular validator system where each security check is implemented as an independent validator that inherits from `BaseValidator`. This allows for easy extension and customization of security policies.

## Current Limitations

- **No code analysis**: Does not inspect actual package source code
- **No malware detection**: Cannot detect malicious code within packages  
- **No vulnerability database**: Does not check against known CVE databases
- **Metadata-only analysis**: Relies solely on PyPI metadata for validation

## Planned Features

### Enhanced Security Validation
- Integration with vulnerability databases (OSV, Safety DB, Python Advisory Database)
- Static code analysis for suspicious patterns in setup.py and package code
- Malware detection using known malicious code signatures
- Dependency chain analysis for deep dependency risks

### Advanced Analysis
- Package integrity verification using cryptographic signatures
- Repository activity analysis (GitHub stars, commit frequency, contributor count)
- License compatibility checking
- Download statistics and popularity metrics validation

### Improved User Experience
- Caching system for package metadata to improve performance
- Offline mode with local vulnerability database
- Integration with virtual environments and requirements.txt files
- Detailed reporting and audit trails
