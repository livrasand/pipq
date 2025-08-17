# pipq

A secure pip proxy that analyzes Python packages before installation to detect potential security issues and risks.

![PyPI](https://img.shields.io/pypi/v/pypipq) [![PyPI Downloads](https://static.pepy.tech/badge/pypipq)](https://pepy.tech/projects/pypipq) [![PyPI Downloads](https://static.pepy.tech/badge/pypipq/week)](https://pepy.tech/projects/pypipq)

## Overview

pipq is a command-line tool that acts as a security layer between you and pip. It intercepts package installation requests, analyzes packages for potential security threats, and provides warnings or blocks installation based on configurable security policies.

## Installation

```bash
pip install pypipq
````

## Usage

Replace `pip install` with `pipq install`:

```bash
pipq install <package-name>
pipq check <package-name>
pipq audit --json
```

### `pipq install` — Secure Installation

```bash
pipq install <package-name>           
pipq install --dev                  
pipq install --force <package-name> 
pipq install --silent <package-name>
pipq install --config /path/config.toml
```

### `pipq check` — Analyze Only (no install)

```bash
pipq check <package-name>
pipq check <package-name>==<version>
pipq check --deep <package-name>
pipq check --depth 3 <package-name>
pipq check --json <package-name>
pipq check --md <package-name>
pipq check --html <package-name>
```

### `pipq audit` — Full Environment Audit

```bash
pipq audit
pipq audit --json
pipq audit --html
pipq audit --fix   # experimental self-healing
```

### `pipq list` — Security Status of Installed Packages

```bash
pipq list
pipq list --vulnerable
```

### `pipq upgrade` — Secure Upgrades

```bash
pipq upgrade <package-name>
pipq upgrade --all
pipq upgrade --security-only
pipq upgrade --dry-run --all
```

### `pipq info` — Detailed Security Profile

```bash
pipq info requests
# shows: version, license, security score (A–F), GPG signatures, etc.
```

### `pipq config` — Manage Configuration

```bash
pipq config list
pipq config get mode
pipq config set mode block
pipq config set auto_continue_warnings true
pipq config reset
```

### `pipq search` — Security-Scored Package Search

```bash
pipq search <package-name>
```

### Aliases

```bash
pipq i <package-name>
pipq ls              
pipq s <package-name>
```

### Global Options

```bash
pipq --version
pipq --verbose
pipq --debug
pipq --help
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

## Architecture

pipq is built on a modular validator system. Each security check is an independent validator that inherits from `BaseValidator`. This design makes it easy to extend or customize security policies.

---

## Current Implementation Status

### Fully Implemented

**Static Code Analysis**
- Full AST parsing 
- Detection of dangerous functions
- Detection of suspicious imports
- Detection of encoded content
- Safe by design (no code execution)

**Integrity Verification**
- SHA256 verification against PyPI metadata
- Detection of non-HTTPS URLs
- Integrity validation

**Provenance Checks**
- Source repository validation (GitHub, GitLab, Bitbucket)
- Detection of `pyproject.toml` and modern packaging standards
- Project URL validation

**Vulnerability Databases**
- OSV (Open Source Vulnerabilities) fully integrated
- Safety DB integration with local caching
- Caching system with DBM for performance

**Repository Activity Analysis**
- GitHub API integration (stars, forks, issues)
- Basic GitLab detection
- Popularity metrics from pepy.tech API

**License Compatibility**
- License detection from classifiers
- Identification of restrictive licenses (GPL, AGPL)
- OSI-approved license analysis

**Caching System**
- Vulnerability DB with DBM and file-based fallback
- Safety DB cache with expiration
- Graceful fallback if cache fails

**Environment Integration**
- Support for `requirements.txt`
- Parsing of `pyproject.toml` (dependencies and dev-dependencies)
- Basic detection of `setup.py`
- Pipfile support

---

### Partially Implemented

**Malware Detection**
- VirusTotal API integration functional
- Basic pattern detection (IPs, crypto-related keywords)
- Signature-based detection not implemented
- Limited obfuscation detection

**Dependency Chain Analysis**
- Basic dependency parsing
- `--deep` option for extended scanning
- Recursive risk scoring not implemented
- Only basic transitive vulnerability checks

**Cryptographic Signatures**
- GPG signature detection in metadata
- Signature verification not fully functional
- No support for PEP 458/480

---

### Not Implemented

**Enhanced Security Validation**
```python
# Placeholder validators
class NewBinValidator(BaseValidator):
    def _validate(self) -> None:
        self.add_info("New Binary Check", "Not yet implemented.")

class SignaturesValidator(BaseValidator): 
    def _validate(self) -> None:
        self.add_info("Signature Check", "Not yet implemented.")

class ScriptsValidator(BaseValidator):
    def _validate(self) -> None:
        self.add_info("Install Script Check", "Not yet implemented.")
````

**Python Advisory Database Integration**

* Not implemented (currently only OSV and Safety DB are supported)

**Advanced Repository Analysis**

* Commit frequency analysis not implemented
* Contributor diversity analysis not implemented
* Advanced license compatibility rules not implemented

**Detailed Reporting**

* Audit trails not implemented
* Historical vulnerability tracking not implemented
* Risk trend analysis not implemented

---

## Completion Summary

| Category                 | Implemented | Partial | Planned |
| ------------------------ | ----------- | ------- | ------- |
| Static Analysis          | 95%         | -       | 5%      |
| Integrity Verification   | 100%        | -       | -       |
| Provenance Checks        | 90%         | -       | 10%     |
| Vulnerability Databases  | 80%         | -       | 20%     |
| Malware Detection        | 60%         | 40%     | -       |
| Repository Analysis      | 70%         | 30%     | -       |
| Cryptographic Signatures | 30%         | 70%     | -       |
| UX / Configuration       | 85%         | 15%     | -       |

Overall, about 75–80% of core features are already implemented in version 0.3.0. The foundation is strong, with most critical security checks fully operational.
