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
- **Malware Scanning**: Uses VirusTotal API to detect malware in package files.

### User Experience
- Rich terminal interface with color-coded output and progress indicators.
- Interactive prompts for security decisions.
- Multiple operation modes: silent, warn, or block.
- Comprehensive configuration via TOML files and environment variables.

## Installation

To install pipq, ensure you have Python 3.8+ and pip installed. Run the following command:

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
- Enhanced security validations (e.g., new binary checks, install scripts).
- Python Advisory Database integration.
- Advanced repository analysis (commit frequency, contributor diversity).
- Detailed reporting (audit trails, historical tracking).

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

Overall, 75–80% of core features are implemented in version 0.3.0.

## Author

Livrädo Sandoval · [livrasand@gmail.com](mailto:livrasand@gmail.com)
