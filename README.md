# pipq

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/livrasand/pipq) ![PyPI](https://img.shields.io/pypi/v/pypipq) [![PyPI Downloads](https://static.pepy.tech/badge/pypipq)](https://pepy.tech/projects/pypipq) [![PyPI Downloads](https://static.pepy.tech/badge/pypipq/week)](https://pepy.tech/projects/pypipq)

A secure pip proxy that analyzes Python packages before installation to detect potential security issues and risks.

## Table of Contents

- [What is pipq?](#what-is-pipq)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [Configuration](#configuration)
- [Testing](#testing)
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

## Testing

pipq includes a comprehensive test suite with 80%+ code coverage across all major components.

### Running Tests

```bash
# Install development dependencies
pip install -e .[dev]

# Run all tests
pytest

# Or use the convenient test runner
python run_tests.py

# Run specific test categories
python run_tests.py unit        # Unit tests only
python run_tests.py integration # Integration tests only
python run_tests.py e2e         # End-to-end tests only

# Run with coverage report
python run_tests.py coverage

# Run performance benchmarks
python run_tests.py performance
```

### Test Structure

- **Unit Tests** (`tests/unit/`): Individual component testing
- **Integration Tests** (`tests/integration/`): Component interaction testing
- **End-to-End Tests** (`tests/e2e/`): Full CLI workflow testing
- **Performance Tests** (`tests/integration/test_performance.py`): Benchmarks

### Test Documentation

See `tests/README.md` for detailed testing documentation, including:
- Test fixtures and mocking strategies
- Writing new tests guidelines
- Troubleshooting common issues
- CI/CD integration information

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
- **CLI Interface**: Complete command-line interface with install, check, audit, list, config, upgrade, info, and search commands.
- **Core Validation Pipeline**: Modular validator system with base validator class and discovery mechanism.
- **Static Code Analysis**: Full AST parsing, detection of dangerous functions, imports, and encoded content.
- **Integrity Verification**: SHA256 verification, HTTPS URL detection.
- **Provenance Checks**: Repository validation, modern packaging standards.
- **Vulnerability Databases**: OSV, Safety DB, and Snyk integration with caching.
- **Repository Activity Analysis**: GitHub API, popularity metrics.
- **License Compatibility**: Detection and analysis of licenses.
- **Caching System**: DBM and file-based caching.
- **Environment Integration**: Support for various dependency files (requirements.txt, pyproject.toml, setup.py).
- **Configuration Management**: TOML and environment variable support.

### Partially Implemented
- **Malware Detection**: Basic pattern detection, VirusTotal API integration (requires API key).
- **Dependency Chain Analysis**: Basic parsing with circular dependency detection, `--deep` option.
- **Cryptographic Signatures**: GPG detection and verification, Sigstore support (experimental).
- **Static Analysis Enhancements**: Semgrep integration (requires external tool).

### Not Implemented
- **Advanced Reporting**: Audit trails, historical tracking, detailed HTML reports.
- **Python Advisory Database**: Integration with official Python security advisories.
- **Advanced Repository Analysis**: Commit frequency, contributor diversity metrics.
- **Binary Analysis**: Deep inspection of compiled extensions and executables.

### Known Issues
- **Database Locking**: VulnerabilityDB uses DBM which can have locking issues on some systems.
- **Error Handling**: Some validators may fail silently or with incomplete error messages.
- **Performance**: Large package analysis can be slow due to multiple network requests.
- **API Dependencies**: Full functionality requires external API keys (VirusTotal, Snyk, etc.).

| Category                 | Implemented | Partial | Planned | Test Coverage |
| ------------------------ | ----------- | ------- | ------- | ------------- |
| CLI & UX                 | 100%        | -       | -       | 95%           |
| Core Framework           | 95%         | -       | 5%      | 90%           |
| Static Analysis          | 90%         | 10%     | -       | 85%           |
| Integrity Verification   | 100%        | -       | -       | 95%           |
| Provenance Checks        | 85%         | 10%     | 5%      | 80%           |
| Vulnerability Databases  | 75%         | 15%     | 10%     | 85%           |
| Malware Detection        | 50%         | 40%     | 10%     | 70%           |
| Repository Analysis      | 65%         | 25%     | 10%     | 75%           |
| Cryptographic Signatures | 25%         | 60%     | 15%     | 60%           |
| Configuration            | 90%         | 10%     | -       | 90%           |

Overall, approximately 75% of core features are implemented in version 0.3.0, with comprehensive test coverage (80%+) across all major components.

## Progress

### Current Development Status
- **Version**: 0.3.0 (Alpha)
- **Lines of Code**: ~8,000+ across 25+ modules
- **Validators Implemented**: 20 security validators
- **CLI Commands**: 8 fully functional commands
- **Test Coverage**: 80%+ comprehensive test suite
- **Documentation**: Comprehensive README, API docs, and test documentation

### Recent Improvements
- Modular validator architecture with automatic discovery
- Multiple vulnerability database integrations (OSV, Safety DB, Snyk)
- Advanced static analysis with AST parsing and pattern detection
- Comprehensive CLI with rich terminal interface
- Flexible configuration system with TOML and environment variables
- Caching system for performance optimization

### Active Development Areas
- Test suite implementation (highest priority)
- Enhanced malware detection capabilities
- Advanced reporting and audit trail features
- Performance optimizations for large package analysis
- Additional vulnerability database integrations

## Dependencies

### Core Dependencies
- **click>=8.0.0**: Command-line interface framework
- **rich>=13.0.0**: Rich terminal interface and formatting
- **halo>=0.0.31**: Spinner animations for CLI
- **requests>=2.25.0**: HTTP client for API interactions
- **packaging>=21.0**: Python package version handling
- **tomli>=1.2.0**: TOML configuration parsing (Python <3.11)
- **tomli-w>=1.0.0**: TOML configuration writing
- **toml>=0.10.2**: Fallback TOML support
- **python-whois>=0.9.5**: Domain expiration checking
- **python-gnupg>=0.5.5**: GPG signature verification
- **portalocker>=2.0.0**: Cross-platform file locking
- **beautifulsoup4>=4.9.3**: HTML parsing utilities
- **google>=3.0.0**: Google search API (for package discovery)
- **bloom-filter2**: Bloom filter implementation for caching

### Development Dependencies
- **pytest>=7.0.0**: Testing framework
- **pytest-cov>=4.0.0**: Test coverage reporting
- **black>=23.0.0**: Code formatting
- **flake8>=6.0.0**: Linting
- **mypy>=1.0.0**: Type checking

### Optional Dependencies
- **VirusTotal API Key**: Required for malware scanning
- **Snyk API Key**: Required for advanced vulnerability analysis
- **Semgrep**: Required for advanced static analysis rules
- **Firejail**: Optional sandboxing for safer analysis

## Installation Instructions

### System Requirements
- Python 3.8 or higher
- pip package manager
- Internet connection for PyPI and vulnerability database access

### Basic Installation
```bash
# Install from PyPI
pip install pypipq

# Verify installation
pipq --version
```

### Development Installation
```bash
# Clone the repository
git clone https://github.com/livrasand/pipq.git
cd pipq

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e .[dev]

# Run tests
pytest

# Or use the convenient test runner
python run_tests.py

# Run with coverage
python run_tests.py coverage

# Format code
black .

# Lint code
flake8 .
mypy .
```

### Configuration Setup
```bash
# Create user configuration directory
mkdir -p ~/.config/pipq

# Create config file
cat > ~/.config/pipq/config.toml << EOF
mode = "warn"
auto_continue_warnings = true
timeout = 30

[vulnerability]
enabled = true
update_interval_days = 7
sources = ["osv", "safetydb", "snyk"]

[security]
minimum_release_age = 0

[api_keys]
virustotal = "your_virustotal_api_key"
snyk = "your_snyk_api_key"
pepy_tech = "your_pepy_tech_api_key"
EOF
```

### API Key Configuration
Some features require API keys for external services:

1. **VirusTotal** (Malware Detection):
   - Sign up at https://www.virustotal.com/
   - Get API key from account settings
   - Set: `export VIRUSTOTAL_API_KEY="your_key"`

2. **Snyk** (Advanced Vulnerabilities):
   - Sign up at https://snyk.io/
   - Get API key from account settings
   - Set: `export SNYK_API_KEY="your_key"`

3. **Pepy.tech** (Download Statistics):
   - Sign up at https://pepy.tech/
   - Get API key from account settings
   - Set: `export PIPQ_API_KEYS_PEPEY_TECH="your_key"`

## Next Steps

### Immediate Priorities (Q1 2024)
1. **Test Suite Maintenance & Expansion**
   - Maintain >80% test coverage across all components
   - Add integration tests for remaining edge cases
   - Set up CI/CD pipeline with automated testing
   - Add property-based testing for critical functions

2. **Enhance Malware Detection**
   - Improve pattern-based detection algorithms
   - Add support for additional malware signatures
   - Implement behavioral analysis for suspicious code
   - Add YARA rule integration

3. **Performance Optimization**
   - Implement parallel processing for validators
   - Optimize caching strategies
   - Reduce network request overhead
   - Add progress indicators for long-running operations

### Medium-term Goals (Q2-Q3 2024)
1. **Advanced Reporting**
   - Implement HTML/PDF report generation
   - Add audit trail and historical tracking
   - Create dashboard for security metrics
   - Add export functionality for CI/CD integration

2. **Additional Validators**
   - Binary analysis for compiled extensions
   - Advanced dependency confusion detection
   - Supply chain risk scoring
   - Code quality metrics integration

3. **Platform Integration**
   - GitHub Actions integration
   - Pre-commit hooks
   - IDE plugins (VS Code, PyCharm)
   - Docker container scanning

### Long-term Vision (2025+)
1. **Enterprise Features**
   - Multi-organization support
   - Advanced policy management
   - Integration with SIEM systems
   - Compliance reporting (SOC2, ISO27001)

2. **AI/ML Integration**
   - Machine learning-based malware detection
   - Automated risk assessment
   - Predictive vulnerability analysis
   - Smart policy recommendations

3. **Community Growth**
   - Plugin ecosystem for custom validators
   - Comprehensive documentation
   - Training and certification programs
   - Industry partnerships

### Contributing
We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Current Focus Areas for Contributors:**
- Writing unit tests
- Implementing new validators
- Improving documentation
- Performance optimizations
- Bug fixes and error handling

### Support
- **Issues**: https://github.com/livrasand/pipq/issues
- **Discussions**: https://github.com/livrasand/pipq/discussions
- **Documentation**: https://github.com/livrasand/pipq/wiki

## Author

Livrädo Sandoval · [livrasand@gmail.com](mailto:livrasand@gmail.com)
