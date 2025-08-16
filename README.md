# pipq

A secure pip proxy that analyzes Python packages before installation to detect potential security issues and risks.

![PyPI](https://img.shields.io/pypi/v/pypipq) [![PyPI Downloads](https://static.pepy.tech/badge/pypipq)](https://pepy.tech/projects/pypipq) 

## Overview

pipq is a command-line tool that acts as a security layer between you and pip. It intercepts package installation requests, analyzes packages for potential security threats, and provides warnings or blocks installation based on configurable security policies.

## Installation

```bash
pip install pypipq
````

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

## Key Functionality

### Implemented and Operational

#### Package Analysis

* **Typosquatting Detection**: Identifies packages with names similar to popular packages that might be masquerading as legitimate libraries
* **Package Age Validation**: Flags packages that are suspiciously new (potential supply chain attacks) or very old without updates (potential abandonment)
* **Maintainer Analysis**: Detects packages maintained by a single individual, indicating higher risk of abandonment
* **License Validation**: Detects missing or problematic licenses
* **Integrity Validation**: Verifies package integrity by validating SHA256 hashes against PyPI metadata.
* **Provenance Analysis**: Checks for a valid source repository URL and modern packaging standards (`pyproject.toml`).
* **Static Code Analysis**: Performs static analysis on package source code to detect suspicious patterns like `eval()`, `exec()`, and suspicious API usage.
* **Vulnerability Scanning**: Checks for known vulnerabilities using the OSV (Open Source Vulnerabilities) database.
* **Malware Scanning**: Scans package files for malware using the VirusTotal API.

#### User Experience

* Rich terminal interface with colored output and progress indicators
* Interactive prompts for security decisions
* Multiple operation modes: silent, warn, or block
* Comprehensive configuration system via TOML files and environment variables

### Partially Implemented

* **Vulnerability scanning**: While OSV integration is functional, planned integrations with Safety DB and the Python Advisory Database are not yet implemented.

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

# API keys for MalwareValidator
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
```

### Getting a VirusTotal API Key

To use the malware scanning features, you need a free VirusTotal API key. Here's how to get one:

1.  **Create a free account** on the [VirusTotal website](https://www.virustotal.com/gui/join-us).
2.  **Sign in** to your account.
3.  Click on your **username** in the top right corner and select **API Key**.
4.  Copy your API key and set it as an environment variable:

    ```bash
    export VIRUSTOTAL_API_KEY="your_new_api_key"
    ```

## Installation Workflow

```bash
pipq install requests           # Analyze and install if safe
pipq check suspicious-package   # Analyze without installing
pipq install --force package    # Skip analysis entirely
```

## Architecture

pipq uses a modular validator system where each security check is implemented as an independent validator that inherits from `BaseValidator`. This allows for easy extension and customization of security policies.

## Key Security Features

pipq goes beyond simple metadata checks and analyzes the actual package contents to provide robust protection against supply chain attacks.

* **Static Code Analysis**: pipq parses the source code of the package using Abstract Syntax Trees (AST) to detect suspicious patterns without executing the code. This can reveal malicious behavior like unexpected network connections, file system manipulation, or obfuscated code.

* **Integrity Verification**: The tool verifies the integrity of the downloaded package by comparing its SHA256 hash with the hash provided by PyPI. This ensures the package has not been tampered with in transit.

* **Provenance Checks**: pipq checks for signs of good project health and maintenance, such as the presence of a source code repository on a reputable platform and the use of modern packaging standards.

## Planned Features

### Enhanced Security Validation

* Integration with vulnerability databases (OSV, Safety DB, Python Advisory Database)
* Static code analysis for suspicious patterns in setup.py and package code
* Malware detection using known malicious code signatures
* Dependency chain analysis for deep dependency risks

### Advanced Analysis

* Package integrity verification using cryptographic signatures
* Repository activity analysis (GitHub stars, commit frequency, contributor count)
* License compatibility checking
* Download statistics and popularity metrics validation

### Improved User Experience

* Caching system for package metadata to improve performance
* Integration with virtual environments and requirements.txt files
* Detailed reporting and audit trails
