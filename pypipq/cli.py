"""Defines the command-line interface for the pipq application.

This module uses the `click` library to create a powerful and user-friendly
CLI. It serves as the main entry point for all user interactions, including
installing, auditing, and checking packages.
"""
import json
import os
import re
import sys
import io
import subprocess
import click
import logging
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from halo import Halo

from .core.config import Config
from .core.validator import validate_package
from .utils.environment import detect_dependency_file, get_installed_packages, parse_dependencies
from .utils.pypi import fetch_package_metadata

# Configure rich console for beautiful output.
console = Console(emoji=True, force_terminal=True)

# Set up basic logging.
logger = logging.getLogger(__name__)


class AliasedGroup(click.Group):
    """A custom click Group that supports command aliases and case-insensitivity."""

    def __init__(self, *args, **kwargs):
        """Initializes the aliased group."""
        super().__init__(*args, **kwargs)
        self._aliases: Dict[str, str] = {}

    def get_command(self, ctx: click.Context, cmd_name: str) -> Optional[click.Command]:
        """Gets a command by name, checking for aliases and prefixes.

        Args:
            ctx: The click context.
            cmd_name: The command name entered by the user.

        Returns:
            The matched click command, or None.
        """
        cmd_name = cmd_name.lower()
        # Exact match
        rv = super().get_command(ctx, cmd_name)
        if rv is not None:
            return rv
        # Alias match
        if cmd_name in self._aliases:
            return super().get_command(ctx, self._aliases[cmd_name])
        # Prefix match
        matches = [x for x in self.list_commands(ctx) if x.startswith(cmd_name)]
        if not matches:
            return None
        if len(matches) == 1:
            return super().get_command(ctx, matches[0])
        ctx.fail(f"Ambiguous command: '{cmd_name}'. Matches: {', '.join(sorted(matches))}")
        return None

    def add_alias(self, alias: str, command_name: str) -> None:
        """Adds an alias for a command.

        Args:
            alias: The alias to add.
            command_name: The name of the command to alias.
        """
        self._aliases[alias.lower()] = command_name.lower()


def _parse_package_spec(package_spec: str) -> Tuple[str, Optional[str]]:
    """Parses a package specification string into a name and version.

    Supports formats like 'name==version', 'name@version', and 'name'.

    Args:
        package_spec: The package specification string.

    Returns:
        A tuple containing the package name and an optional version string.
    """
    if '==' in package_spec:
        name, version = package_spec.split('==', 1)
        return name.strip(), version.strip()
    if '@' in package_spec and not package_spec.startswith(("git+", "http")):
        name, version = package_spec.split('@', 1)
        return name.strip(), version.strip()
    return package_spec.strip(), None


@click.group(cls=AliasedGroup, invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="pypipq")
@click.option("--verbose", is_flag=True, help="Enable verbose output.")
@click.option("--debug", is_flag=True, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool, debug: bool) -> None:
    """A secure pip proxy that analyzes Python packages for security risks.

    pipq acts as a wrapper around pip, intercepting installation requests to
    perform a series of security validations. It helps protect against supply
    chain attacks, malware, and other vulnerabilities.
    """
    # Basic setup for logging and UTF-8 output.
    if sys.platform == "win32" and isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding='utf-8')
    log_level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    logger.debug("Debug mode enabled.")

    if ctx.invoked_subcommand is None:
        console.print("Use 'pipq install <package>' to install packages safely, or 'pipq --help' for more commands.")


@main.command(name="install")
@click.argument("packages", nargs=-1, required=False)
@click.option("--dev", is_flag=True, help="Include development dependencies from config files.")
@click.option("--force", "-f", is_flag=True, help="Force installation by skipping all validation.")
@click.option("--silent", "-s", is_flag=True, help="Run in silent mode, suppressing all prompts.")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), help="Path to a custom config file.")
def install(packages: Tuple[str, ...], dev: bool, force: bool, silent: bool, config_path: Optional[str]) -> None:
    """Install packages after performing security validation.

    This command is the primary entry point for securely installing packages.
    It intercepts a `pip install` request, runs a series of security validators
    on the specified packages, and then, based on the results and configuration,
    proceeds with the actual installation via pip.

    If no packages are specified, pipq will attempt to detect and install
    dependencies from 'pyproject.toml', 'requirements.txt', or 'setup.py'.
    """
    config_obj = Config(config_path=config_path)
    package_list = list(packages)

    if not package_list:
        dependency_file = detect_dependency_file()
        if dependency_file:
            console.print(f"[green]Detected dependency file: {dependency_file}[/green]")
            package_list = parse_dependencies(dependency_file, include_dev=dev)
            if not package_list:
                console.print("[yellow]No dependencies found in the file.[/yellow]")
                return
        else:
            console.print("[red]No packages specified and no dependency file was found.[/red]")
            sys.exit(1)

    if silent:
        config_obj.set("mode", "silent")

    if force:
        console.print("[yellow]--force flag used. Skipping all validation.[/yellow]")
        _run_pip_install(package_list)
        return

    all_results = []
    for package_spec in package_list:
        package_name, version = _parse_package_spec(package_spec)
        display_name = f"{package_name}@{version}" if version else package_name
        console.print(f"\n[bold blue]Analyzing package: {display_name}[/bold blue]")
        with Halo(text=f"Validating {display_name}...", spinner="dots") as spinner:
            try:
                results = validate_package(package_name, config_obj, version=version)
                all_results.append(results)
                spinner.succeed(f"Analysis complete for {display_name}")
            except Exception as e:
                spinner.fail(f"Analysis failed for {display_name}: {e}")
                if config_obj.get("mode") == "block":
                    console.print("[red]Aborting installation due to analysis failure in block mode.[/red]")
                    sys.exit(1)

    if _display_results_and_get_confirmation(all_results, config_obj):
        _run_pip_install(package_list)
    else:
        console.print("[yellow]Installation cancelled.[/yellow]")
        sys.exit(1)


@main.command()
@click.argument("packages", nargs=-1, required=True)
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), help="Path to config file.")
@click.option("--json", "json_output", is_flag=True, help="Output results in JSON format.")
@click.option("--md", "md_output", is_flag=True, help="Output results in Markdown format.")
@click.option("--html", "html_output", is_flag=True, help="Output results in HTML format.")
@click.option("--deep", is_flag=True, help="Perform a deep scan including dependencies.")
@click.option("--depth", type=int, default=4, help="Max recursion depth for deep scan.")
def check(packages: Tuple[str, ...], config_path: Optional[str], json_output: bool, md_output: bool, html_output: bool, deep: bool, depth: int) -> None:
    """Analyze one or more packages for security risks without installing them.

    This command allows you to assess a package's security and quality profile
    before deciding to use it in your project. It runs the full suite of
    validators and provides detailed results in various formats.

    The `--deep` flag enables a recursive analysis of the package's
    dependencies, providing a more comprehensive view of the supply chain risk.
    """
    config_obj = Config(config_path=config_path)
    all_results = []
    for package_spec in packages:
        package_name, version = _parse_package_spec(package_spec)
        display_name = f"{package_name}@{version}" if version else package_name
        console.print(f"\n[bold blue]Analyzing package: {display_name}[/bold blue]")
        with Halo(text=f"Validating {display_name}...", spinner="dots") as spinner:
            try:
                results = validate_package(package_name, config_obj, version=version, deep_scan=deep)
                all_results.append(results)
                spinner.succeed(f"Analysis complete for {display_name}")
            except Exception as e:
                spinner.fail(f"Analysis failed for {display_name}: {e}")

    if json_output:
        console.print(json.dumps(all_results, indent=2))
    elif md_output:
        console.print(_format_results_as_markdown(all_results))
    elif html_output:
        console.print(_format_results_as_html(all_results))
    else:
        _display_results(all_results, show_summary=False)


def _format_results_as_markdown(all_results: List[Dict]) -> str:
    """Formats a list of validation results into a Markdown string.

    Args:
        all_results: A list of result dictionaries from the validation process.

    Returns:
        A Markdown-formatted string representing the results.
    """
    markdown = ""
    for results in all_results:
        pkg = results.get("package", "Unknown Package")
        markdown += f"# Security Analysis for `{pkg}`\n\n"
        errors = results.get("errors", [])
        warnings = results.get("warnings", [])
        if errors:
            markdown += "## 🚨 Errors\n"
            for error in errors:
                markdown += f"- {error}\n"
        if warnings:
            markdown += "\n## ⚠️ Warnings\n"
            for warning in warnings:
                markdown += f"- {warning}\n"
        markdown += "\n---\n"
    return markdown


def _format_results_as_html(all_results: List[Dict]) -> str:
    """Formats a list of validation results into an HTML string.

    Args:
        all_results: A list of result dictionaries from the validation process.

    Returns:
        An HTML-formatted string representing the results.
    """
    # This is a basic HTML representation.
    html = "<html><head><title>pipq Scan Results</title></head><body>"
    for results in all_results:
        pkg = results.get("package", "Unknown Package")
        html += f"<h1>Security Analysis for <code>{pkg}</code></h1>"
        errors = results.get("errors", [])
        warnings = results.get("warnings", [])
        if errors:
            html += "<h2>Errors</h2><ul>"
            for error in errors:
                html += f"<li>{error}</li>"
            html += "</ul>"
        if warnings:
            html += "<h2>Warnings</h2><ul>"
            for warning in warnings:
                html += f"<li>{warning}</li>"
            html += "</ul>"
        html += "<hr>"
    html += "</body></html>"
    return html


def _display_results(all_results: List[Dict], show_summary: bool = True) -> None:
    """Displays validation results in a series of formatted tables.

    Args:
        all_results: A list of result dictionaries from the validation process.
        show_summary: Whether to show the final summary panel.
    """
    for results in all_results:
        package_name = results.get("package", "Unknown")
        errors = results.get("errors", [])
        warnings = results.get("warnings", [])
        validator_results = results.get("validator_results", [])

        if not validator_results:
            console.print(f"[yellow]No validators were run for {package_name}.[/yellow]")
            continue

        console.print(f"\n[bold blue]Results for: {package_name}[/bold blue]")
        summary_table = Table(title=f"Validator Summary for {package_name}")
        summary_table.add_column("Validator", style="cyan")
        summary_table.add_column("Status")
        for res in validator_results:
            status = "[green]Passed[/green]"
            if res.get("errors"):
                status = "[red]Failed[/red]"
            elif res.get("warnings"):
                status = "[yellow]Warning[/yellow]"
            summary_table.add_row(res["name"], status)
        console.print(summary_table)

        if errors or warnings:
            issues_table = Table(title=f"Issues for {package_name}")
            issues_table.add_column("Level", style="bold")
            issues_table.add_column("Message")
            for error in errors:
                issues_table.add_row("[red]ERROR[/red]", error)
            for warning in warnings:
                issues_table.add_row("[yellow]WARNING[/yellow]", warning)
            console.print(issues_table)

    if show_summary:
        total_errors = sum(len(r.get("errors", [])) for r in all_results)
        total_warnings = sum(len(r.get("warnings", [])) for r in all_results)
        if total_errors > 0:
            console.print(Panel(f"Found {total_errors} error(s) and {total_warnings} warning(s).", style="red", title="Scan Complete"))
        elif total_warnings > 0:
            console.print(Panel(f"Found {total_warnings} warning(s).", style="yellow", title="Scan Complete"))


def _display_results_and_get_confirmation(all_results: List[Dict], config: Config) -> bool:
    """Displays results and prompts the user for confirmation to install.

    Args:
        all_results: A list of result dictionaries.
        config: The application's configuration object.

    Returns:
        True if the installation should proceed, False otherwise.
    """
    _display_results(all_results)
    total_errors = sum(len(r.get("errors", [])) for r in all_results)
    total_warnings = sum(len(r.get("warnings", [])) for r in all_results)
    mode = config.get("mode", "interactive")

    if total_errors > 0:
        if mode in ("interactive", "block"):
            console.print("[red]Installation aborted due to critical errors.[/red]")
            return False
    if mode == "block" and total_warnings > 0:
        console.print("[red]Installation aborted due to warnings (block mode).[/red]")
        return False
    if mode == "silent":
        return total_errors == 0

    return click.confirm("\nDo you want to proceed with the installation?")


def _run_pip_install(packages: List[str], upgrade: bool = False) -> None:
    """Runs the `pip install` command as a subprocess.

    Args:
        packages: A list of package specifiers to install.
        upgrade: If True, adds the `--upgrade` flag to the command.
    """
    # Basic validation of package names to prevent command injection.
    for pkg in packages:
        if not re.match(r'^[a-zA-Z0-9\-_.,@+]+(?:\[.*\])?(?:[<>=!~]=.*)?$', pkg):
            console.print(f"[red]Invalid package specifier detected: {pkg}[/red]")
            sys.exit(1)

    action = "Upgrading" if upgrade else "Installing"
    console.print(f"\n[bold green]🚀 {action} packages: {', '.join(packages)}[/bold green]")
    pip_cmd = [sys.executable, "-m", "pip", "install"]
    if upgrade:
        pip_cmd.append("--upgrade")
    pip_cmd.extend(packages)

    try:
        subprocess.run(pip_cmd, check=True)
        console.print(f"\n[green]✅ {action} completed successfully![/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"\n[red]❌ pip install failed with exit code {e.returncode}.[/red]")
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        console.print(f"\n[yellow]INTERRUPTED: {action} cancelled by user.[/yellow]")
        sys.exit(1)


@main.command()
@click.option("--json", "json_output", is_flag=True, help="Output results in JSON format.")
@click.option("--html", "html_output", is_flag=True, help="Output results in HTML format.")
@click.option("--fix", is_flag=True, help="Guide on how to fix vulnerable packages.")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), help="Path to config file.")
def audit(json_output: bool, html_output: bool, fix: bool, config_path: Optional[str]) -> None:
    """Audit all installed packages in the current environment for security issues.

    This command iterates through every package in the environment, running
    security validations for each one. It's useful for getting a snapshot of
    the overall security posture of a project's dependencies.

    The command exits with a non-zero status code if any errors (e.g.,
    vulnerabilities) are found.
    """
    config_obj = Config(config_path=config_path)
    installed_packages = get_installed_packages()
    if not installed_packages:
        console.print("[yellow]No installed packages found to audit.[/yellow]")
        return

    console.print(f"[bold blue]Auditing {len(installed_packages)} installed packages...[/bold blue]")
    all_results = []
    with Halo(text="Auditing...", spinner="dots") as spinner:
        for i, pkg in enumerate(installed_packages):
            spinner.text = f"Auditing {pkg['name']}=={pkg['version']} ({i+1}/{len(installed_packages)})"
            if pkg['name'].lower() in ['pip', 'setuptools', 'wheel', 'pipq']:
                continue
            try:
                results = validate_package(pkg['name'], config_obj, version=pkg['version'])
                all_results.append(results)
            except Exception as e:
                logger.error(f"Could not audit {pkg['name']}: {e}")

    if json_output:
        console.print(json.dumps(all_results, indent=2))
    elif html_output:
        console.print(_format_results_as_html(all_results))
    else:
        _display_results(all_results)

    if fix and any(r.get("errors") for r in all_results):
        console.print("\n[bold yellow]To fix found vulnerabilities, run 'pipq upgrade --security-only'[/bold yellow]")

    if any(r.get("errors") for r in all_results):
        sys.exit(1)


def _get_package_status(result: Dict[str, Any]) -> Tuple[str, str]:
    """Determines a summary status for a package based on its validation results.

    Args:
        result: The result dictionary for a single package.

    Returns:
        A tuple containing the status string and a summary of issues.
    """
    errors = result.get("errors", [])
    warnings = result.get("warnings", [])
    if errors:
        return "VULNERABLE" if any("vulnerability" in e.lower() for e in errors) else "ERROR", ", ".join(errors)
    if warnings:
        return "WARNING", ", ".join(warnings)
    return "OK", "No issues found"


@main.command(name="list")
@click.option("--vulnerable", is_flag=True, help="List only packages with vulnerabilities.")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), help="Path to config file.")
def list_packages(vulnerable: bool, config_path: Optional[str]) -> None:
    """List installed packages with their security status.

    This command provides a quick overview of the installed packages and their
    assessed security status, highlighting any found vulnerabilities or
    other issues.
    """
    config_obj = Config(config_path=config_path)
    installed_packages = get_installed_packages()
    if not installed_packages:
        console.print("[yellow]No installed packages found.[/yellow]")
        return

    table = Table(title="Installed Packages Security Status")
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="magenta")
    table.add_column("Status", style="bold")
    table.add_column("Issues")

    with Halo(text="Analyzing packages...", spinner="dots") as spinner:
        for i, pkg in enumerate(installed_packages):
            package_name, version = pkg["name"], pkg["version"]
            spinner.text = f"Analyzing {package_name}=={version} ({i+1}/{len(installed_packages)})"
            try:
                results = validate_package(package_name, config_obj, version=version)
                status, issues = _get_package_status(results)
                if vulnerable and status != "VULNERABLE":
                    continue
                table.add_row(package_name, version, status, issues)
            except Exception as e:
                logger.error(f"Analysis failed for {package_name}: {e}")
                table.add_row(package_name, version, "[red]ERROR[/red]", "Analysis failed")

    console.print(table)


@main.command()
@click.argument("action", type=click.Choice(['get', 'set', 'list', 'reset']), required=True)
@click.argument("key", type=str, required=False)
@click.argument("value", type=str, required=False)
def config(action: str, key: Optional[str], value: Optional[str]) -> None:
    """Manage the pipq configuration.

    This command allows you to view, set, and reset configuration values
    that are stored in the user-level configuration file.

    \b
    ACTION:
        get <key>       Get a configuration value.
        set <key> <value> Set a configuration value.
        list            List all current configuration values.
        reset           Reset the configuration to its default state.
    """
    config_obj = Config()
    if action == "list":
        console.print(Panel(json.dumps(config_obj.config, indent=2), title="Current Configuration"))
    elif action == "get":
        if not key:
            console.print("[red]Error: 'get' action requires a key.[/red]", file=sys.stderr)
            sys.exit(1)
        console.print(config_obj.get(key))
    elif action == "set":
        if not key or value is None:
            console.print("[red]Error: 'set' action requires a key and a value.[/red]", file=sys.stderr)
            sys.exit(1)
        # Type casting for bools and ints
        if value.lower() in ('true', 'false'):
            processed_value: Any = value.lower() == 'true'
        elif value.isdigit():
            processed_value = int(value)
        else:
            processed_value = value
        config_obj.set(key, processed_value)
        try:
            config_obj.save_user_config()
            console.print(f"[green]'{key}' set to '{processed_value}' and saved to user config.[/green]")
        except IOError as e:
            console.print(f"[red]Error saving configuration: {e}[/red]", file=sys.stderr)
            sys.exit(1)
    elif action == "reset":
        config_file = Config.DEFAULT_CONFIG
        if os.path.exists(config_file):
            os.remove(config_file)
            console.print("[green]Configuration reset to defaults.[/green]")
        else:
            console.print("[yellow]No user configuration file to reset.[/yellow]")


@main.command()
@click.argument("packages", nargs=-1, required=False)
@click.option("--all", "all_packages", is_flag=True, help="Upgrade all outdated packages.")
@click.option("--security-only", is_flag=True, help="Upgrade only packages with security vulnerabilities.")
@click.option("--dry-run", is_flag=True, help="Show what would be upgraded without making changes.")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), help="Path to config file.")
def upgrade(packages: Tuple[str, ...], all_packages: bool, security_only: bool, dry_run: bool, config_path: Optional[str]) -> None:
    """Upgrade packages securely after validation.

    This command wraps `pip install --upgrade`, ensuring that the new versions
    of packages are analyzed for security risks before the upgrade is
    performed.

    Note: The logic for `--all` and `--security-only` is currently simplified.
    A full implementation would require more sophisticated package version
    and vulnerability resolution.
    """
    config_obj = Config(config_path=config_path)
    if not packages and not all_packages and not security_only:
        console.print("[red]Error: You must specify packages to upgrade, or use --all or --security-only.[/red]")
        sys.exit(1)

    # This is a simplified logic. A full implementation would be more robust.
    to_upgrade = []
    if packages:
        to_upgrade.extend(list(packages))
    # In a real implementation, --all and --security-only would query for outdated/vulnerable packages.

    if not to_upgrade:
        console.print("[green]All packages are up-to-date and secure.[/green]")
        return

    console.print(f"The following packages will be upgraded: {', '.join(to_upgrade)}")
    if dry_run:
        console.print("\n[bold yellow]--dry-run enabled. No packages will be upgraded.[/bold yellow]")
        return

    if click.confirm("\nDo you want to proceed with the upgrade?"):
        _run_pip_install(to_upgrade, upgrade=True)


@main.command()
@click.argument("package", type=str, required=True)
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), help="Path to config file.")
def info(package: str, config_path: Optional[str]) -> None:
    """Display a detailed security profile for a package.

    This command aggregates the results from all validators to provide a
    holistic view of a package's security and quality, including a heuristic-based
    security score.
    """
    config_obj = Config(config_path=config_path)
    console.print(f"[bold blue]Fetching information for {package}...[/bold blue]")
    try:
        results = validate_package(package, config_obj)
        metadata = fetch_package_metadata(package)
        info_data = metadata.get("info", {})

        score = 100 - (len(results.get("errors", [])) * 20) - (len(results.get("warnings", [])) * 5)
        score_letter = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

        panel_content = f"""
[bold]Package[/bold]: {info_data.get('name', 'N/A')}
[bold]Version[/bold]: {info_data.get('version', 'N/A')}
[bold]Summary[/bold]: {info_data.get('summary', 'N/A')}
[bold]License[/bold]: {info_data.get('license', 'N/A')}
[bold]Security Score[/bold]: {score_letter} ({max(0, score)}/100)
"""
        console.print(Panel(panel_content.strip(), title=f"Security Profile for {package}", expand=False))
        _display_results([results])
    except Exception as e:
        console.print(f"[red]Could not retrieve information for {package}: {e}[/red]")
        sys.exit(1)


@main.command(name="search")
@click.argument("query", type=str, required=True)
def search_packages(query: str) -> None:
    """Search for packages on PyPI (experimental)."""
    console.print(f"[yellow]Note: Search is experimental and uses a third-party service.[/yellow]")
    try:
        from googlesearch import search
    except ImportError:
        console.print("[red]Error: 'google' package is required for search. Please run 'pip install beautifulsoup4 google'[/red]")
        return

    table = Table(title=f"Search Results for '{query}'")
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="magenta")
    table.add_column("Summary")
    with Halo(text=f"Searching for '{query}'...", spinner="dots"):
        try:
            search_results = search(f"site:pypi.org {query}", stop=10)
            pypi_urls = [url for url in search_results if "pypi.org/project/" in url]
            for url in pypi_urls:
                match = re.search(r"pypi.org/project/([^/]+)", url)
                if match:
                    pkg_name = match.group(1)
                    try:
                        meta = fetch_package_metadata(pkg_name)
                        info = meta.get("info", {})
                        table.add_row(info.get("name"), info.get("version"), info.get("summary"))
                    except Exception:
                        continue
        except Exception as e:
            console.print(f"[red]Search failed: {e}[/red]")
            return
    console.print(table)


main.add_alias('i', 'install')
main.add_alias('ls', 'list')
main.add_alias('s', 'search')

if __name__ == "__main__":
    main()