"""
Command-line interface for pipq.

This module provides the main entry point for the pipq command.
"""
import json
import os
import sys
import io
import subprocess
import click
import logging
from typing import Any, Dict, List, Optional, Tuple
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
if os.name == 'nt':
    os.system('chcp 65001')
    os.environ['PYTHONIOENCODING'] = 'utf-8'
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from halo import Halo

from halo import Halo

from .core.config import Config
from .core.validator import validate_package
from .utils.environment import detect_dependency_file, get_installed_packages, parse_dependencies
from .utils.pypi import fetch_package_metadata


console = Console(emoji=True, force_terminal=True)


class AliasedGroup(click.Group):
    """A click group that allows aliases for commands."""
    def __init__(self, *args, **kwargs):
        super(AliasedGroup, self).__init__(*args, **kwargs)
        self._aliases = {}

    def get_command(self, ctx, cmd_name):
        # Allow case-insensitive commands
        cmd_name = cmd_name.lower()

        # Exact match
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv

        # Check aliases
        if cmd_name in self._aliases:
            return click.Group.get_command(self, ctx, self._aliases[cmd_name])

        # Match prefixes
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        if len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])

        ctx.fail(f"Too many matches for '{cmd_name}': {', '.join(sorted(matches))}")
        return None # Unreachable, but for clarity

    def add_alias(self, alias, command_name):
        self._aliases[alias.lower()] = command_name.lower()


def _parse_package_spec(package_spec: str) -> Tuple[str, Optional[str]]:
    """
    Parse package specification into name and version.
    Supports 'name==version', 'name@version', and 'name'.
    
    Args:
        package_spec: Package specification string.
    
    Returns:
        A tuple of (package_name, version_specifier).
        Version is None if not specified.
    """
    if '==' in package_spec:
        name, version = package_spec.split('==', 1)
        return name.strip(), version.strip()
    if '@' in package_spec:
        # Avoid treating email-style VCS URLs as package@version
        if not package_spec.startswith("git+") and not package_spec.startswith("http"):
            name, version = package_spec.split('@', 1)
            return name.strip(), version.strip()
    return package_spec.strip(), None


@click.group(cls=AliasedGroup, invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show version and exit")
@click.option("--verbose",  is_flag=True, help="Verbose output")
@click.option("--debug", is_flag=True, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, version: bool, verbose: bool, debug: bool) -> None:
    """
    pipq - A secure pip proxy inspired.
    
    Analyzes packages before installation to detect potential security issues.
    """
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.debug("Debug mode enabled.")
    
    if version:
        from pypipq import __version__
        console.print(f"pypipq version {__version__}")
        return
    
    if ctx.invoked_subcommand is None:
        console.print("Use 'pipq install <package>' to install packages safely.")
        console.print("Use 'pipq --help' for more information.")


@main.command(name="install", 
    short_help="Install packages after security validation.",
    help="""Install packages after security validation.

    If no packages are specified, pipq will attempt to install dependencies
    from 'pyproject.toml', 'requirements.txt', or 'setup.py' in that order.

    Use the --dev flag to include development dependencies from 'pyproject.toml'.
    """
)
@click.argument("packages", nargs=-1, required=False)
@click.option("--dev", is_flag=True, help="Include development dependencies.")
@click.option("--force", "-f", is_flag=True, help="Skip validation and install directly")
@click.option("--silent", "-s", is_flag=True, help="Run in silent mode (no prompts)")
@click.option("--config", type=click.Path(exists=True), help="Path to config file")
def install(packages: List[str], dev: bool, force: bool, silent: bool, config: Optional[str]) -> None:
    logger = logging.getLogger(__name__)
    logger.info(f"Starting install command for packages: {packages}")
    # Load configuration
    config_obj = Config(config_path=config)

    # Convert tuple to list to allow modification
    packages = list(packages)

    # If no packages are specified, detect dependency file
    if not packages:
        dependency_file = detect_dependency_file()
        if dependency_file:
            console.print(f"[green]Detected dependency file: {dependency_file}[/green]")
            packages = parse_dependencies(dependency_file, include_dev=dev)
            if not packages:
                console.print("[yellow]No dependencies found in the file.[/yellow]")
                return
        else:
            console.print("[red]No packages specified and no dependency file found.[/red]")
            return

    # Override mode if silent flag is used
    if silent:
        config_obj.set("mode", "silent")
    
    # If force flag is used, skip validation entirely
    if force:
        console.print("[yellow]Skipping validation (--force flag used)[/yellow]")
        _run_pip_install(packages)
        return
    
    # Validate each package
    all_results = []
    for package_spec in packages:
        package_name, version = _parse_package_spec(package_spec)
        display_name = f"{package_name}@{version}" if version else package_name
        
        console.print(f"\n[bold blue]Analyzing package: {display_name}[/bold blue]")
        
        with Halo(text=f"Validating {display_name}...", spinner="dots") as spinner:
            try:
                results = validate_package(package_name, config_obj, version=version)
                all_results.append(results)
                spinner.succeed(f"Analysis complete for {display_name}")
            except Exception as e:
                spinner.fail(f"Analysis failed for {display_name}: {str(e)}")
                if not _should_continue_on_error(config_obj):
                    console.print(f"[red]Aborting installation due to ana               lysis failure.[/red]")
                    sys.exit(1)
                continue
    
    # Display results
    should_install = _display_results_and_get_confirmation(all_results, config_obj)
    
    if should_install:
        _run_pip_install(packages)
    else:
        console.print("[yellow]Installation cancelled.[/yellow]")
        sys.exit(1)


@main.command()
@click.argument("packages", nargs=-1, required=True)
@click.option("--config", type=click.Path(exists=True), help="Path to config file")
@click.option("--json", "json_output", is_flag=True, help="Output results in JSON format")
@click.option("--md", "md_output", is_flag=True, help="Output results in Markdown format")
@click.option("--html", "html_output", is_flag=True, help="Output results in HTML format")
@click.option("--deep", is_flag=True, help="Perform a deep scan including dependencies.")
@click.option("--depth", type=int, default=4, help="Max recursion depth for deep scan.")
def check(packages: List[str], config: Optional[str], json_output: bool, md_output: bool, html_output: bool, deep: bool, depth: int) -> None:
    logger = logging.getLogger(__name__)
    logger.info(f"Starting check command for packages: {packages} with deep_scan={deep} and depth={depth}")
    """
    Check one or more packages without installing them.
    
    PACKAGES: One or more package names to analyze (can include versions with ==)
    """
    config_obj = Config(config_path=config)
    all_results = []
    for package_spec in packages:
        package_name, version = _parse_package_spec(package_spec)
        display_name = f"{package_name}@{version}" if version else package_name
        
        console.print(f"[bold blue]Analyzing package: {display_name}[/bold blue]")
        
        with Halo(text=f"Validating {display_name}...", spinner="dots") as spinner:
            try:
                results = validate_package(package_name, config_obj, version=version, deep_scan=deep, depth=depth)
                all_results.append(results)
                spinner.succeed(f"Analysis complete for {display_name}")
            except Exception as e:
                spinner.fail(f"Analysis failed for {display_name}: {str(e)}")
                console.print(f"[red]Could not analyze package: {str(e)}[/red]")
                continue
    
    if json_output:
        console.print(json.dumps(all_results, indent=4))
    elif md_output:
        console.print(_format_results_as_markdown(all_results))
    elif html_output:
        console.print(_format_results_as_html(all_results))
    else:
        _display_results(all_results, show_summary=False)


def _format_results_as_markdown(all_results: List[dict]) -> str:
    """Format validation results as a Markdown string."""
    markdown = ""
    for results in all_results:
        package_name = results["package"]
        errors = results.get("errors", [])
        warnings = results.get("warnings", [])
        validator_results = results.get("validator_results", [])

        markdown += f"# Results for: {package_name}\n\n"

        # Summary Table
        markdown += "| Validator | Category | Status |\n"
        markdown += "| --- | --- | --- |\n"
        for val_result in validator_results:
            val_name = val_result["name"]
            val_category = val_result["category"]
            status = "Passed"
            if val_result["errors"]:
                status = "Failed"
            elif val_result["warnings"]:
                status = "Warning"
            markdown += f"| {val_name} | {val_category} | {status} |\n"
        markdown += "\n"

        # Issues Table
        if errors or warnings:
            markdown += "| Type | Message |\n"
            markdown += "| --- | --- |\n"
            for error in errors:
                markdown += f"| ERROR | {error} |\n"
            for warning in warnings:
                markdown += f"| WARNING | {warning} |\n"
            markdown += "\n"

        # Detailed Validator Results
        for val_result in validator_results:
            val_name = val_result["name"]
            val_category = val_result["category"]
            val_errors = val_result["errors"]
            val_warnings = val_result["warnings"]
            val_info = val_result["info"]

            if val_errors or val_warnings or val_info:
                markdown += f"## Validator: {val_name} ({val_category})\n\n"
                markdown += "| Type | Message |\n"
                markdown += "| --- | --- |\n"
                for err in val_errors:
                    markdown += f"| ERROR | {err} |\n"
                for warn in val_warnings:
                    markdown += f"| WARNING | {warn} |\n"
                for key, value in val_info.items():
                    markdown += f"| INFO | {key}: {value} |\n"
                markdown += "\n"
    return markdown


def _format_results_as_html(all_results: List[dict]) -> str:
    """Format validation results as an HTML string."""
    # This is a placeholder for a more sophisticated HTML report.
    # For now, we'll just dump the JSON into a <pre> tag.
    return f"<pre>{json.dumps(all_results, indent=4)}</pre>"


def _display_results(all_results: List[dict], show_summary: bool = True) -> None:
    """Display validation results in a formatted table."""
    
    for results in all_results:
        package_name = results["package"]
        errors = results.get("errors", [])
        warnings = results.get("warnings", [])
        validator_results = results.get("validator_results", [])
        
        if not validator_results:
            console.print(f"[yellow]{package_name}: No validators were run.[/yellow]")
            continue

        console.print(f"\n[bold blue]Results for: {package_name}[/bold blue]")

        # Display summary of validators
        summary_table = Table(title=f"Validators Summary for {package_name}")
        summary_table.add_column("Validator", style="bold")
        summary_table.add_column("Category", style="bold")
        summary_table.add_column("Status", style="bold")

        has_issues = False
        for val_result in validator_results:
            val_name = val_result["name"]
            val_category = val_result["category"]
            status = "[green]Passed[/green]"
            if val_result["errors"]:
                status = "[red]Failed[/red]"
                has_issues = True
            elif val_result["warnings"]:
                status = "[yellow]Warning[/yellow]"
                has_issues = True
            summary_table.add_row(val_name, val_category, status)
        
        console.print(summary_table)
        console.print()

        if not has_issues:
            console.print(f"[green]{package_name}: No issues found[/green]")
            #continue

        # Display aggregated errors and warnings
        if errors or warnings:
            table = Table(title=f"Aggregated Issues for {package_name}")
            table.add_column("Type", style="bold")
            table.add_column("Message")

            for error in errors:
                table.add_row("ERROR", f"[red]{error}[/red]")
            for warning in warnings:
                table.add_row("WARNING", f"[yellow]{warning}[/yellow]")
            console.print(table)
            console.print()

        # Display detailed validator results
        for val_result in validator_results:
            val_name = val_result["name"]
            val_category = val_result["category"]
            val_description = val_result["description"]
            val_errors = val_result["errors"]
            val_warnings = val_result["warnings"]
            val_info = val_result["info"]

            if val_errors or val_warnings or val_info:
                table = Table(title=f"Validator: {val_name} ({val_category})")
                table.add_column("Type", style="bold")
                table.add_column("Message")

                if val_description:
                    table.add_row("INFO", f"[cyan]{val_description}[/cyan]")

                for err in val_errors:
                    table.add_row("ERROR", f"[red]{err}[/red]")
                for warn in val_warnings:
                    table.add_row("WARNING", f"[yellow]{warn}[/yellow]")
                for key, value in val_info.items():
                    table.add_row("INFO", f"[magenta]{key}: {value}[/magenta]")
                console.print(table)
                console.print()
    
    if show_summary:
        total_errors = sum(len(r.get("errors", [])) for r in all_results)
        total_warnings = sum(len(r.get("warnings", [])) for r in all_results)
        
        if total_errors > 0 or total_warnings > 0:
            summary_text = f"Summary: {total_errors} error(s), {total_warnings} warning(s)"
            if total_errors > 0:
                console.print(Panel(summary_text, style="red", title="Security Summary"))
            else:
                console.print(Panel(summary_text, style="yellow", title="Security Summary"))



def _display_results_and_get_confirmation(all_results: List[dict], config: Config) -> bool:
    """Display validation results and get user confirmation to install."""
    _display_results(all_results, show_summary=True)

    total_errors = sum(len(r.get("errors", [])) for r in all_results)
    total_warnings = sum(len(r.get("warnings", [])) for r in all_results)
    mode = config.get("mode", "interactive")

    if total_errors > 0:
        console.print("[red]Installation aborted due to critical errors.[/red]")
        return False

    if mode == "silent":
        return True

    if mode == "block":
        if total_warnings > 0:
            console.print("[red]Installation aborted due to warnings (block mode).[/red]")
            return False
        return True

    # Interactive mode
    if total_warnings > 0:
        console.print(f"[yellow]Found {total_warnings} warning(s).[/yellow]")

    return click.confirm("Do you want to proceed with the installation?")


def _should_continue_on_error(config: Config) -> bool:
    """Check if we should continue on analysis errors."""
    return config.get("mode") != "block"


def _run_pip_install(packages: List[str], upgrade: bool = False) -> None:
    """
    Run the actual pip install command.
    
    Args:
        packages: List of package names to install.
        upgrade: Whether to run 'pip install --upgrade'.
    """
    action = "Upgrading" if upgrade else "Installing"
    console.print(f"[bold green]{action} packages: {', '.join(packages)}[/bold green]")
    
    # Build pip command
    pip_cmd = [sys.executable, "-m", "pip", "install"]
    if upgrade:
        pip_cmd.append("--upgrade")
    pip_cmd.extend(list(packages))
    
    try:
        # Run pip install and stream output
        subprocess.run(pip_cmd, check=True, capture_output=False)
        console.print(f"[green]{action} completed successfully![/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]pip install failed with exit code {e.returncode}[/red]")
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        console.print(f"\\n[yellow]{action} interrupted by user[/yellow]")
        sys.exit(1)


@main.command()
@click.option("--json", "json_output", is_flag=True, help="Output results in JSON format.")
@click.option("--html", "html_output", is_flag=True, help="Output results in HTML format.")
@click.option("--fix", is_flag=True, help="Automatically upgrade vulnerable packages.")
@click.option("--config", type=click.Path(exists=True), help="Path to config file")
def audit(json_output: bool, html_output: bool, fix: bool, config: Optional[str]) -> None:
    logger = logging.getLogger(__name__)
    logger.info("Starting audit command.")
    """
    Audit all installed packages in the current environment for security issues.
    """
    config_obj = Config(config_path=config)
    installed_packages = get_installed_packages()

    if not installed_packages:
        console.print("[yellow]No installed packages found to audit.[/yellow]")
        return

    console.print(f"[bold blue]Auditing {len(installed_packages)} installed packages...[/bold blue]")

    all_results = []
    vulnerable_packages = []
    with Halo(text="Auditing...", spinner="dots") as spinner:
        for i, pkg in enumerate(installed_packages):
            package_name = pkg["name"]
            version = pkg["version"]
            spinner.text = f"Auditing {package_name}=={version} ({i+1}/{len(installed_packages)})"
            try:
                # We skip packages that are fundamental to pip's operation
                if package_name.lower() in ['pip', 'setuptools', 'wheel', 'pipq']:
                    continue
                results = validate_package(package_name, config_obj, version=version)
                all_results.append(results)
                if results.get("errors"):
                    vulnerable_packages.append(results)
            except Exception as e:
                spinner.warn(f"Could not audit {package_name}: {str(e)}")

    if json_output:
        console.print(json.dumps(all_results, indent=4))
        return

    if html_output:
        # Placeholder for now
        console.print(_format_results_as_html(all_results))
        return

    _display_results(all_results, show_summary=True)

    if fix and vulnerable_packages:
        console.print("\n[bold yellow]--fix is not yet fully implemented.[/bold yellow]")
        console.print("To fix vulnerabilities, run 'pipq upgrade --security-only'")

    # Set exit code based on findings
    if any(res.get("errors") for res in all_results):
        sys.exit(1)


def _get_package_status(result: Dict[str, Any]) -> Tuple[str, str]:
    """Determine the status and issues for a package from its validation result."""
    errors = result.get("errors", [])
    warnings = result.get("warnings", [])

    if errors:
        # Check for specific vulnerability errors
        if any("vulnerability" in err.lower() for err in errors):
            return "🔒 VULN", ", ".join(errors)
        return "🔥 ERROR", ", ".join(errors)

    if warnings:
        # Check for age warnings
        if any("age" in warn.lower() for warn in warnings):
            return "⚠️ OLD", ", ".join(warnings)
        return "🤔 WARN", ", ".join(warnings)

    return "✅ OK", "None"


@main.command(name="list")
@click.option("--vulnerable", is_flag=True, help="List only packages with vulnerabilities.")
@click.option("--config", type=click.Path(exists=True), help="Path to config file")
def list_packages(vulnerable: bool, config: Optional[str]) -> None:
    logger = logging.getLogger(__name__)
    logger.info("Starting list_packages command.")
    """
    List installed packages with their security status.
    """
    config_obj = Config(config_path=config)
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
            package_name = pkg["name"]
            version = pkg["version"]
            spinner.text = f"Analyzing {package_name}=={version} ({i+1}/{len(installed_packages)})"

            try:
                # For 'list', we can run a slightly lighter validation if needed
                # For now, we run the full validation to be safe
                results = validate_package(package_name, config_obj, version=version)
                status, issues = _get_package_status(results)

                if vulnerable and "VULN" not in status:
                    continue

                table.add_row(package_name, version, status, issues)
            except Exception:
                table.add_row(package_name, version, "📊 CHECK", "Analysis failed")

    console.print(table)


@main.command()
@click.argument("action", type=click.Choice(['get', 'set', 'list', 'reset']), required=True)
@click.argument("key", type=str, required=False)
@click.argument("value", type=str, required=False)
def config(action: str, key: Optional[str], value: Optional[str]) -> None:
    """
    Manage pipq configuration.

    ACTION:
        get <key>: Get a configuration value.
        set <key> <value>: Set a configuration value.
        list: List all configuration values.
        reset: Reset configuration to defaults.
    """
    config_obj = Config()

    if action == "list":
        table = Table(title="pipq Configuration")
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="magenta")
        for k, v in sorted(config_obj.config.items()):
            table.add_row(str(k), str(v))
        console.print(table)

    elif action == "get":
        if not key:
            console.print("[red]Error: 'get' action requires a key.[/red]")
            sys.exit(1)
        retrieved_value = config_obj.get(key)
        if retrieved_value is not None:
            console.print(f"{key} = {retrieved_value}")
        else:
            console.print(f"'{key}' not found in configuration.")
            sys.exit(1)

    elif action == "set":
        if not key or value is None:
            console.print("[red]Error: 'set' action requires a key and a value.[/red]")
            sys.exit(1)

        # Attempt to convert value to bool or int if applicable
        if value.lower() in ['true', 'false']:
            processed_value = value.lower() == 'true'
        elif value.isdigit():
            processed_value = int(value)
        else:
            processed_value = value

        config_obj.set(key, processed_value)
        try:
            config_obj.save_user_config()
            console.print(f"[green]'{key}' set to '{processed_value}'[/green]")
        except IOError as e:
            console.print(f"[red]Error saving configuration: {e}[/red]")
            sys.exit(1)

    elif action == "reset":
        from .core.config import USER_CONFIG_PATH
        if USER_CONFIG_PATH.exists():
            USER_CONFIG_PATH.unlink()
            console.print("[green]Configuration reset to defaults.[/green]")
        else:
            console.print("[yellow]No user configuration file to reset.[/yellow]")


@main.command()
@click.argument("packages", nargs=-1, required=False)
@click.option("--all", "all_packages", is_flag=True, help="Upgrade all outdated packages.")
@click.option("--security-only", is_flag=True, help="Upgrade only packages with security vulnerabilities.")
@click.option("--dry-run", is_flag=True, help="Show what would be upgraded, but don't upgrade.")
@click.option("--config", type=click.Path(exists=True), help="Path to config file")
def upgrade(
    packages: List[str],
    all_packages: bool,
    security_only: bool,
    dry_run: bool,
    config: Optional[str],
) -> None:
    logger = logging.getLogger(__name__)
    logger.info(f"Starting upgrade command for packages: {packages}")
    """
    Upgrade packages securely.
    """
    config_obj = Config(config_path=config)

    if not packages and not all_packages and not security_only:
        console.print("[red]Error: You must specify packages to upgrade, or use --all or --security-only.[/red]")
        return

    to_upgrade = []

    # Logic for single package upgrade
    if packages:
        installed_map = {p["name"].lower(): p["version"] for p in get_installed_packages()}
        for pkg_name in packages:
            if pkg_name.lower() not in installed_map:
                console.print(f"[yellow]Package '{pkg_name}' is not installed. Skipping.[/yellow]")
                continue

            current_version = installed_map[pkg_name.lower()]
            try:
                metadata = fetch_package_metadata(pkg_name)
                latest_version = metadata.get("info", {}).get("version")

                if latest_version and latest_version != current_version:
                    # Avoid duplicates
                    if not any(p['name'] == pkg_name for p in to_upgrade):
                        to_upgrade.append({
                            "name": pkg_name,
                            "current": current_version,
                            "latest": latest_version
                        })
                else:
                    console.print(f"[green]Package '{pkg_name}' is already up-to-date.[/green]")
            except Exception as e:
                console.print(f"[red]Could not fetch metadata for {pkg_name}: {e}[/red]")

    # Logic for --all
    if all_packages:
        installed_packages = get_installed_packages()
        with Halo(text="Checking for outdated packages...", spinner="dots") as spinner:
            for i, pkg in enumerate(installed_packages):
                spinner.text = f"Checking {pkg['name']} ({i+1}/{len(installed_packages)})"
                if pkg['name'].lower() in ['pip', 'setuptools', 'wheel', 'pipq']:
                    continue
                try:
                    metadata = fetch_package_metadata(pkg['name'])
                    latest_version = metadata.get("info", {}).get("version")
                    if latest_version and latest_version != pkg['version']:
                        if not any(p['name'] == pkg['name'] for p in to_upgrade):
                            to_upgrade.append({
                                "name": pkg['name'],
                                "current": pkg['version'],
                                "latest": latest_version
                            })
                except Exception:
                    pass # Ignore packages that can't be fetched

    # Logic for --security-only
    if security_only:
        installed_packages = get_installed_packages()
        with Halo(text="Scanning for vulnerabilities...", spinner="dots") as spinner:
            for i, pkg in enumerate(installed_packages):
                spinner.text = f"Scanning {pkg['name']} ({i+1}/{len(installed_packages)})"
                if pkg['name'].lower() in ['pip', 'setuptools', 'wheel', 'pipq']:
                    continue
                try:
                    results = validate_package(pkg['name'], config_obj, version=pkg['version'])
                    if results.get("errors"):
                         metadata = fetch_package_metadata(pkg['name'])
                         latest_version = metadata.get("info", {}).get("version")
                         if latest_version and latest_version != pkg['version']:
                            # Check if the latest version is secure
                            latest_results = validate_package(pkg['name'], config_obj, version=latest_version)
                            if not latest_results.get("errors"):
                                if not any(p['name'] == pkg['name'] for p in to_upgrade):
                                    to_upgrade.append({
                                        "name": pkg['name'],
                                        "current": pkg['version'],
                                        "latest": latest_version
                                    })
                except Exception:
                    pass

    if not to_upgrade:
        console.print("[green]Everything is up-to-date and secure.[/green]")
        return

    # Display what will be upgraded
    table = Table(title="Packages to Upgrade")
    table.add_column("Package", style="cyan")
    table.add_column("Current", style="red")
    table.add_column("Latest", style="green")
    for pkg in to_upgrade:
        table.add_row(pkg["name"], pkg["current"], pkg["latest"])
    console.print(table)

    if dry_run:
        console.print("\n[bold yellow]--dry-run enabled. No packages will be upgraded.[/bold yellow]")
        return

    # Get confirmation and validate before upgrade
    if click.confirm("\nDo you want to proceed with the upgrade?"):
        validated_to_upgrade = []
        for pkg in to_upgrade:
            console.print(f"\n[bold blue]Validating {pkg['name']}=={pkg['latest']} before upgrade...[/bold blue]")
            results = validate_package(pkg['name'], config_obj, version=pkg['latest'])
            _display_results([results], show_summary=False)
            if not results.get("errors"):
                validated_to_upgrade.append(pkg['name'])
            else:
                console.print(f"[red]Skipping upgrade for {pkg['name']} due to validation errors.[/red]")

        if validated_to_upgrade:
            _run_pip_install(validated_to_upgrade, upgrade=True)


@main.command()
@click.argument("package", type=str, required=True)
@click.option("--config", type=click.Path(exists=True), help="Path to config file")
def info(package: str, config: Optional[str]) -> None:
    logger = logging.getLogger(__name__)
    logger.info(f"Starting info command for package: {package}")
    """
    Display detailed information and a security profile for a package.
    """
    config_obj = Config(config_path=config)

    console.print(f"[bold blue]Fetching information for {package}...[/bold blue]")
    try:
        results = validate_package(package, config_obj)
        metadata = fetch_package_metadata(package) # We need the raw metadata again
        info_data = metadata.get("info", {})

        # Security Score (a simple heuristic for now)
        score = 100
        if results.get("errors"):
            score -= 50 * len(results.get("errors"))
        if results.get("warnings"):
            score -= 10 * len(results.get("warnings"))
        score_letter = "A+" if score >= 95 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

        panel_content = f"""
[bold]Name[/bold]: {info_data.get('name', 'N/A')}
[bold]Latest Version[/bold]: {info_data.get('version', 'N/A')}
[bold]Summary[/bold]: {info_data.get('summary', 'N/A')}
[bold]License[/bold]: {info_data.get('license', 'N/A')}
[bold]Requires Python[/bold]: {info_data.get('requires_python', 'N/A')}
[bold]Homepage[/bold]: {info_data.get('home_page', 'N/A')}

[bold]Security Score[/bold]: {score_letter} ({max(0, score)}/100)
"""
        # Extract specific validator info
        for res in results.get("validator_results", []):
            if res['name'] == 'GPGValidator':
                panel_content += f"[bold]GPG Signed[/bold]: {'Yes ✅' if not res.get('errors') else 'No ❌'}\n"
            if res['name'] == 'MaintainerValidator':
                panel_content += f"[bold]Maintainers[/bold]: {res.get('info', {}).get('maintainer_count', 'N/A')}\n"

        console.print(Panel(panel_content.strip(), title=f"pipq info for {package}", expand=False))

        # Display issues found
        _display_results([results], show_summary=True)

    except Exception as e:
        console.print(f"[red]Could not retrieve information for {package}: {e}[/red]")


@main.command(name="search")
@click.argument("query", type=str, required=True)
def search_packages(query: str) -> None:
    """
    Search for packages on PyPI with security scoring.

    This is a placeholder and uses an external search to find packages.
    """
    console.print(f"[bold blue]Searching for '{query}' on PyPI...[/bold blue]")
    console.print("[yellow]Note: Search functionality is experimental.[/yellow]")

    # This is a creative workaround as there's no simple PyPI search API
    # In a real-world scenario, we'd use a more robust method.
    try:
        import re
        from googlesearch import search
    except ImportError:
        console.print("[red]Error: 'google' package not installed. Please run 'pip install beautifulsoup4 google'[/red]")
        return

    table = Table(title=f"Search results for '{query}'")
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="magenta")
    table.add_column("Summary")

    try:
        search_results = search(f"site:pypi.org {query}", stop=10)
        pypi_urls = [url for url in search_results if "pypi.org/project/" in url]

        for url in pypi_urls:
            match = re.search(r"pypi.org/project/([^/]+)", url)
            if match:
                package_name = match.group(1)
                try:
                    metadata = fetch_package_metadata(package_name)
                    info = metadata.get("info", {})
                    table.add_row(
                        info.get("name", "N/A"),
                        info.get("version", "N/A"),
                        info.get("summary", "")
                    )
                except Exception:
                    continue # Ignore if metadata fetch fails
        console.print(table)
    except Exception as e:
        console.print(f"[red]Search failed: {e}[/red]")


# Add aliases
main.add_alias('i', 'install')
main.add_alias('ls', 'list')
main.add_alias('s', 'search')


if __name__ == "__main__":
    main()