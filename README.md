# pipq

![PyPI](https://img.shields.io/pypi/v/pypipq) [![PyPI Downloads](https://static.pepy.tech/badge/pypipq)](https://pepy.tech/projects/pypipq) [![PyPI Downloads](https://static.pepy.tech/badge/pypipq/week)](https://pepy.tech/projects/pypipq)

A secure pip proxy that analyzes Python packages before installation to detect potential security issues and risks.

## Table of Contents

- [What is pipq?](#what-is-pipq)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [Configuration](#configuration)
- [Benefits](#benefits)
- [Practical Examples](#practical-examples)
- [FAQ](#faq)
- [Architecture](#architecture)
- [Implementation Status](#implementation-status)
- [Author](#author)

## What is pipq?

pipq is a command-line security tool designed to enhance the safety of Python package installations. Acting as an intermediary between users and pip, pipq intercepts package installation requests, performs comprehensive security analyses, and provides actionable insights or blocks potentially harmful packages based on configurable policies. This tool is particularly valuable for developers, DevOps teams, and organizations seeking to mitigate risks associated with supply chain attacks, malware, and other security vulnerabilities in the Python ecosystem.

> [!WARNING]
> pipq is experimental and offers no API or CLI compatibility guarantees.

## Key Features

pipq offers a robust suite of security validations to protect against various threats:

### Package Analysis
- **Typosquatting Detection**: Identifies packages with names similar to popular ones, which may be malicious imitations.
- **Package Age Validation**: Flags newly created packages that could indicate supply chain attacks or very old packages lacking updates.
- **Maintainer Analysis**: Assesses maintainer profiles, highlighting risks from single-maintainer packages.
- **License Validation**: Ensures packages have valid, non-problematic licenses.
- **Integrity Validation**: Verifies package integrity using SHA256 hashes against PyPI metadata.
- **Provenance Analysis**: Checks for valid source repositories and adherence to modern packaging standards (e.g., `pyproject.toml`).
- **Static Code Analysis**: Scans source code for dangerous patterns like `eval()`, `exec()`, and suspicious API usage without executing code.
- **Vulnerability Scanning**: Queries databases like OSV for known vulnerabilities.
- **Malware Scanning**: Scans for suspicious code patterns and uses the VirusTotal API to detect known malware.
- **Dependency Analysis**: Checks for circular dependencies and an excessive number of dependencies.
- **Cryptographic Signature Verification**: Verifies GPG signatures and checks for the presence of modern TUF and Sigstore signatures.

### User Experience
- Rich terminal interface with color-coded output and progress indicators.
- Interactive prompts for security decisions.
- Multiple operation modes: `interactive`, `silent`, or `block`.
- Comprehensive configuration via TOML files and environment variables.

## Installation

To install `pypipq`, ensure you have Python 3.8+ and pip installed. Run the following command:

```bash
pip install pypipq
```

After installation, verify the setup:

```bash
pipq --version
```

## Quick Start

Replace standard `pip install` commands with `pipq install` for secure installations:

```bash
pipq install requests
```

pipq will analyze the package and proceed based on your configuration (warn, block, or silent mode).

## Detailed Usage

### Secure Installation
```bash
pipq install <package-name>           # Install with security checks
pipq install --dev                    # Install development dependencies
pipq install --force <package-name>   # Force installation despite warnings
pipq install --silent <package-name>  # Suppress output
pipq install --config /path/config.toml  # Use custom config file
```

### Analyze Without Installing
```bash
pipq check <package-name>             # Basic analysis
pipq check <package-name>==<version>  # Check specific version
pipq check --deep <package-name>      # Deep dependency analysis
pipq check --depth 3 <package-name>   # Limit analysis depth
pipq check --json <package-name>      # Output in JSON format
pipq check --md <package-name>        # Output in Markdown
pipq check --html <package-name>      # Output in HTML
```

### Full Environment Audit
```bash
pipq audit                            # Audit installed packages
pipq audit --json                     # JSON output
pipq audit --html                     # HTML report
pipq audit --fix                      # Experimental self-healing
```

### Security Status of Installed Packages
```bash
pipq list                             # List all packages with security status
pipq list --vulnerable                # Show only vulnerable packages
```

### Secure Upgrades
```bash
pipq upgrade <package-name>           # Upgrade specific package securely
pipq upgrade --all                    # Upgrade all packages
pipq upgrade --security-only          # Upgrade only security-related updates
pipq upgrade --dry-run --all          # Preview upgrades without applying
```

### Detailed Security Profile
```bash
pipq info requests                    # Shows version, license, security score (A–F), GPG signatures, etc.
```

### Configuration Management
```bash
pipq config list                      # List current settings
pipq config get mode                  # Get specific setting
pipq config set mode block            # Set operation mode to block
pipq config set auto_continue_warnings true  # Auto-continue on warnings
pipq config reset                     # Reset to defaults
```

### Security-Scored Package Search
```bash
pipq search <package-name>            # Search with security scores
```

### Aliases
```bash
pipq i <package-name>                 # Alias for install
pipq ls                               # Alias for list
pipq s <package-name>                 # Alias for search
```

### Global Options
```bash
pipq --version                        # Show version
pipq --verbose                        # Verbose output
pipq --debug                          # Debug mode
pipq --help                           # Show help
```

## Configuration

pipq supports flexible configuration via TOML files and environment variables.

Create `~/.config/pipq/config.toml`:

```toml
mode = "warn"                    # silent, warn, or block
auto_continue_warnings = true
disable_validators = []
timeout = 30
```

Or use environment variables:

```bash
export pipq_MODE=block
export pipq_DISABLE_VALIDATORS=age,maintainer

# API keys for MalwareValidator
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
```

### Obtaining a VirusTotal API Key

To enable malware scanning:

1. Create a free account on the [VirusTotal website](https://www.virustotal.com/gui/join-us).
2. Sign in to your account.
3. Click your username in the top right and select **API Key**.
4. Copy the key and set it as an environment variable:

```bash
export VIRUSTOTAL_API_KEY="your_new_api_key"
```

## Benefits

### For Individuals
- **Personal Security**: Protect your development environment from malicious packages that could compromise your data or system.
- **Awareness**: Gain insights into package risks, helping you make informed decisions.
- **Ease of Use**: Seamlessly integrates with existing pip workflows without significant overhead.

### For Enterprises
- **Supply Chain Protection**: Mitigate risks from third-party dependencies in production environments.
- **Compliance**: Assist in meeting security standards and regulatory requirements.
- **Operational Efficiency**: Automate security checks, reducing manual review efforts and potential human error.
- **Scalability**: Suitable for large-scale deployments with configurable policies tailored to organizational needs.

pipq enhances overall software supply chain security by providing proactive threat detection and risk assessment.

## Validators

`pypipq` includes a comprehensive suite of validators to inspect different aspects of a package's quality and security.

| Validator | Category | Description |
| --- | --- | --- |
| **Age** | Quality | Checks if a package is suspiciously new or old and unmaintained. |
| **Cryptographic** | Cryptographic Integrity | Verifies GPG signatures of downloaded packages. |
| **Dependency** | Risk | Analyzes package dependencies for potential issues. |
| **ExpiredDomains** | Security | Checks for expired domains in maintainer and author emails. |
| **GPG** | Security | Checks for the presence of GPG signatures in package releases. |
| **Integrity** | Package Integrity | Verifies that the downloaded package's hash matches the one listed in PyPI. |
| **License** | Legal & Compliance | Checks for missing, ambiguous, or restrictive licenses. |
| **Maintainer** | Quality | Detects packages with a single maintainer or limited community support. |
| **MalwareDetector** | Security | Scans package files for suspicious patterns indicative of malware. |
| **NewBinaries** | Security | *Placeholder:* Detects if a new version of a package introduces new binary files. |
| **Popularity** | Community | Checks the download popularity of a package via the Pepy.tech API. |
| **Provenance** | Security | Verifies package provenance from its repository and build files. |
| **ReleaseAge** | Supply Chain Security | Enforces a minimum age for releases to mitigate fast-moving supply chain attacks. |
| **InstallScripts** | Security | *Placeholder:* Detects the presence of potentially malicious pre- or post-installation scripts. |
| **Signatures** | Cryptographic Integrity | Checks for modern package signatures (e.g., TUF, Sigstore). |
| **Size** | Quality | Checks for abnormally large package sizes, which could indicate bundled binaries. |
| **Source** | Community | Analyzes the source code repository for activity and health metrics. |
| **StaticAnalysis** | Security | Scans package for malware and suspicious code patterns. |
| **Typosquat** | Security | Detects packages with names deceptively similar to popular ones. |
| **Vulnerabilities** | Security | Checks for known vulnerabilities using multiple advisory databases. |

## Practical Examples

### Example 1: Installing a Popular Package
```bash
pipq install requests
```
pipq analyzes `requests`, checks for vulnerabilities, and installs if safe. If issues are found, it warns or blocks based on your mode.

### Example 2: Auditing an Existing Environment
```bash
pipq audit --json > audit_report.json
```
Generates a JSON report of all installed packages' security status for review or integration into CI/CD pipelines.

### Example 3: Checking a Specific Version
```bash
pipq check numpy==1.21.0 --deep
```
Performs deep analysis on NumPy version 1.21.0, including dependencies, and outputs detailed security information.

### Example 4: Secure Upgrade Process
```bash
pipq upgrade --all --dry-run
```
Previews upgrades for all packages, showing potential security improvements without making changes.

## FAQ

### What is pipq?
pipq is a security wrapper for pip that analyzes Python packages for potential threats before installation, helping prevent supply chain attacks and malware.

### How does pipq differ from pip?
pipq adds security layers on top of pip, including vulnerability scanning, malware detection, and integrity checks, without altering pip's core functionality.

### Is pipq safe to use in production?
While functional, pipq is experimental. Test thoroughly in staging environments before production use. It offers no compatibility guarantees.

### Can pipq replace pip entirely?
pipq is designed to work alongside pip. Use `pipq install` instead of `pip install` for security-enhanced installations.

### What if pipq blocks a legitimate package?
Configure pipq to warn instead of block, or use `--force` for exceptions. Review the analysis output to understand the concern.

### Does pipq slow down installations?
Analysis adds some overhead, but caching and efficient checks minimize impact. For large environments, consider batch operations.

### How do I report issues or contribute?
Report bugs or feature requests via GitHub issues. Contributions are welcome; see the repository for guidelines.

### Is pipq compatible with all Python versions?
pipq requires Python 3.8+. Compatibility with older versions is not guaranteed.

### Can I use pipq with virtual environments?
Yes, pipq works within virtual environments. Activate your venv and use pipq as usual.

### What data does pipq collect?
pipq does not collect or transmit user data. All analysis is local, though it may query public APIs like VirusTotal or PyPI.

## Architecture

pipq is built on a modular validator system. Each security check is an independent validator inheriting from `BaseValidator`, allowing easy extension and customization of security policies.

## Implementation Status

### Fully Implemented
- **Static Code Analysis**: Full AST parsing, detection of dangerous functions, imports, and encoded content.
- **Integrity Verification**: SHA256 verification, HTTPS URL detection.
- **Provenance Checks**: Repository validation, modern packaging standards.
- **Vulnerability Databases**: OSV and Safety DB integration with caching.
- **Repository Activity Analysis**: GitHub API, popularity metrics.
- **License Compatibility**: Detection and analysis of licenses.
- **Caching System**: DBM and file-based caching.
- **Environment Integration**: Support for various dependency files.

### Partially Implemented
- **Malware Detection**: VirusTotal API, basic pattern detection.
- **Dependency Chain Analysis**: Basic parsing, `--deep` option.
- **Cryptographic Signatures**: GPG detection, partial verification.

### Not Implemented
- Enhanced security validations (e.g., new binary checks, install scripts are currently placeholders).
- Python Advisory Database integration.
- Advanced repository analysis (commit frequency, contributor diversity).
- Detailed reporting (audit trails, historical tracking).

| Category | Implemented | Partial | Planned | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **Core Engine** | 95% | - | 5% | Core validation logic is robust. |
| **Static Analysis** | 80% | 15% | 5% | AST parsing is solid; sandboxing is experimental. |
| **Integrity Checks** | 100% | - | - | SHA256 and HTTPS checks are fully implemented. |
| **Provenance & Source**| 85% | 10% | 5% | Good support for GitHub; other platforms are basic. |
| **Vulnerability DBs** | 90% | - | 10% | OSV, SafetyDB, and Snyk integration is complete. |
| **Malware Detection** | 50% | 50% | - | Basic pattern matching and VirusTotal API are implemented. |
| **Crypto Signatures** | 40% | 60% | - | GPG verification is functional; TUF/Sigstore are basic checks. |
| **Community & Quality**| 90% | - | 10% | Age, popularity, license, and maintainer checks are solid. |
| **CLI & UX** | 90% | 10% | - | Most commands are implemented; reporting can be improved. |

Overall, 80-85% of core features are implemented in version 0.4.0.

## Author

Livrädo Sandoval · [livrasand@gmail.com](mailto:livrasand@gmail.com)
