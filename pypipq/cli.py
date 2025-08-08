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
from typing import List, Optional, Tuple
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
if os.name == 'nt':
    os.system('chcp 65001')
    os.environ['PYTHONIOENCODING'] = 'utf-8'
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from halo import Halo

from .core.config import Config
from .core.validator import validate_package


console = Console(emoji=True, force_terminal=True)


def _parse_package_spec(package_spec: str) -> str:
    """Parse package specification into name.
    
    Args:
        package_spec: Package specification (e.g. "flask" or "flask==2.0.1")
    
    Returns:
        Package name
    """
    if '==' in package_spec:
        return package_spec.split('==', 1)[0]
    return package_spec


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show version and exit")
@click.option("--verbose",  is_flag=True, help="Verbose output")
@click.pass_context
def main(ctx: click.Context, version: bool, verbose: bool) -> None:
    """
    pipq - A secure pip proxy inspired.
    
    Analyzes packages before installation to detect potential security issues.
    """
    if version:
        from pypipq import __version__
        console.print(f"pypipq version {__version__}")
        return
    
    if ctx.invoked_subcommand is None:
        console.print("Use 'pipq install <package>' to install packages safely.")
        console.print("Use 'pipq --help' for more information.")


@main.command()
@click.argument("packages", nargs=-1, required=True)
@click.option("--force", "-f", is_flag=True, help="Skip validation and install directly")
@click.option("--silent", "-s", is_flag=True, help="Run in silent mode (no prompts)")
@click.option("--config", type=click.Path(exists=True), help="Path to config file")
def install(packages: List[str], force: bool, silent: bool, config: Optional[str]) -> None:
    """
    Install packages after security validation.
    
    PACKAGES: One or more package names to install (can include versions with ==)
    """
    # Load configuration
    config_obj = Config(config_path=config)
    
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
        package_name = _parse_package_spec(package_spec)
        display_name = package_name
        
        console.print(f"\n[bold blue]Analyzing package: {display_name}[/bold blue]")
        
        with Halo(text=f"Validating {display_name}...", spinner="dots") as spinner:
            try:
                results = validate_package(package_name, config_obj)
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
def check(packages: List[str], config: Optional[str], json_output: bool, md_output: bool, html_output: bool) -> None:
    """
    Check one or more packages without installing them.
    
    PACKAGES: One or more package names to analyze (can include versions with ==)
    """
    config_obj = Config(config_path=config)
    all_results = []
    for package_spec in packages:
        package_name = _parse_package_spec(package_spec)
        display_name = package_name
        
        console.print(f"[bold blue]Analyzing package: {display_name}[/bold blue]")
        
        with Halo(text=f"Validating {display_name}...", spinner="dots") as spinner:
            try:
                results = validate_package(package_name, config_obj)
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
        
        if not errors and not warnings and not validator_results:
            console.print(f"[green]{package_name}: No issues found[/green]")
            continue
        
        console.print(f"\n[bold blue]Results for: {package_name}[/bold blue]")

        # Display summary of validators
        summary_table = Table(title=f"Validators Summary for {package_name}")
        summary_table.add_column("Validator", style="bold")
        summary_table.add_column("Category", style="bold")
        summary_table.add_column("Status", style="bold")

        for val_result in validator_results:
            val_name = val_result["name"]
            val_category = val_result["category"]
            status = "[green]Passed[/green]"
            if val_result["errors"]:
                status = "[red]Failed[/red]"
            elif val_result["warnings"]:
                status = "[yellow]Warning[/yellow]"
            summary_table.add_row(val_name, val_category, status)
        
        console.print(summary_table)
        console.print()

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


def _run_pip_install(packages: List[str]) -> None:
    """
    Run the actual pip install command.
    
    Args:
        packages: List of package names to install
    """
    console.print(f"[bold green]Installing packages: {', '.join(packages)}[/bold green]")
    
    # Build pip command
    pip_cmd = [sys.executable, "-m", "pip", "install"] + list(packages)
    
    try:
        # Run pip install and stream output
        result = subprocess.run(pip_cmd, check=True, capture_output=False)
        console.print("[green]Installation completed successfully![/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]pip install failed with exit code {e.returncode}[/red]")
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        console.print("\\n[yellow]Installation interrupted by user[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    main()