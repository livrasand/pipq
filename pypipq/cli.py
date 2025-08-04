"""
Command-line interface for pypipq.

This module provides the main entry point for the pipq command.
"""

import sys
import subprocess
import click
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from halo import Halo

from .core.config import Config
from .core.validator import validate_package


console = Console()


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version and exit")
@click.pass_context
def main(ctx: click.Context, version: bool) -> None:
    """
    pipq - A secure pip proxy inspired by npq.
    
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
    
    PACKAGES: One or more package names to install
    """
    # Load configuration
    config_obj = Config(config_path=config)
    
    # Override mode if silent flag is used
    if silent:
        config_obj.set("mode", "silent")
    
    # If force flag is used, skip validation entirely
    if force:
        console.print("[yellow]⚠️  Skipping validation (--force flag used)[/yellow]")
        _run_pip_install(packages)
        return
    
    # Validate each package
    all_results = []
    for package in packages:
        console.print(f"\\n[bold blue]📦 Analyzing package: {package}[/bold blue]")
        
        with Halo(text=f"Validating {package}...", spinner="dots") as spinner:
            try:
                results = validate_package(package)
                all_results.append(results)
                spinner.succeed(f"Analysis complete for {package}")
            except Exception as e:
                spinner.fail(f"Analysis failed for {package}: {str(e)}")
                if not _should_continue_on_error(config_obj):
                    console.print(f"[red]❌ Aborting installation due to analysis failure.[/red]")
                    sys.exit(1)
                continue
    
    # Display results
    should_install = _display_results_and_get_confirmation(all_results, config_obj)
    
    if should_install:
        _run_pip_install(packages)
    else:
        console.print("[yellow]📦 Installation cancelled.[/yellow]")
        sys.exit(1)


@main.command()
@click.argument("package", required=True)
@click.option("--config", type=click.Path(exists=True), help="Path to config file")
def check(package: str, config: Optional[str]) -> None:
    """
    Check a package without installing it.
    
    PACKAGE: Package name to analyze
    """
    config_obj = Config(config_path=config)
    
    console.print(f"[bold blue]🔍 Analyzing package: {package}[/bold blue]")
    
    with Halo(text=f"Validating {package}...", spinner="dots") as spinner:
        try:
            results = validate_package(package)
            spinner.succeed(f"Analysis complete for {package}")
        except Exception as e:
            spinner.fail(f"Analysis failed for {package}: {str(e)}")
            console.print(f"[red]❌ Could not analyze package: {str(e)}[/red]")
            sys.exit(1)
    
    _display_results([results], show_summary=False)


def _display_results_and_get_confirmation(all_results: List[dict], config: Config) -> bool:
    """
    Display validation results and get user confirmation if needed.
    
    Returns:
        True if installation should proceed, False otherwise
    """
    has_errors = any(result["errors"] for result in all_results)
    has_warnings = any(result["warnings"] for result in all_results)
    
    # Display results
    _display_results(all_results)
    
    # Check if we should block installation
    if has_errors and config.should_block():
        console.print("[red]🚫 Installation blocked due to security errors.[/red]")
        return False
    
    # Check if we need user confirmation
    if config.get("mode") == "silent":
        return True
    
    if not has_errors and not has_warnings:
        console.print("[green]✅ No issues found. Proceeding with installation.[/green]")
        return True
    
    if has_warnings and config.should_auto_continue():
        console.print("[yellow]⚠️  Warnings found, but auto-continuing as configured.[/yellow]")
        return True
    
    # Prompt user for confirmation
    if has_errors:
        message = "❗ Security errors found. Do you want to continue anyway?"
        default = False
    else:
        message = "⚠️  Warnings found. Do you want to continue with installation?"
        default = True
    
    return click.confirm(message, default=default)


def _display_results(all_results: List[dict], show_summary: bool = True) -> None:
    """Display validation results in a formatted table."""
    
    for results in all_results:
        package_name = results["package"]
        errors = results["errors"]
        warnings = results["warnings"]
        
        if not errors and not warnings:
            console.print(f"[green]✅ {package_name}: No issues found[/green]")
            continue
        
        # Create a table for this package's results
        table = Table(title=f"Analysis Results for {package_name}")
        table.add_column("Type", style="bold")
        table.add_column("Message")
        
        # Add errors
        for error in errors:
            table.add_row("ERROR", f"[red]{error}[/red]")
        
        # Add warnings
        for warning in warnings:
            table.add_row("WARNING", f"[yellow]{warning}[/yellow]")
        
        console.print(table)
        console.print()
    
    if show_summary:
        total_errors = sum(len(r["errors"]) for r in all_results)
        total_warnings = sum(len(r["warnings"]) for r in all_results)
        
        if total_errors > 0 or total_warnings > 0:
            summary_text = f"Summary: {total_errors} error(s), {total_warnings} warning(s)"
            if total_errors > 0:
                console.print(Panel(summary_text, style="red", title="Security Summary"))
            else:
                console.print(Panel(summary_text, style="yellow", title="Security Summary"))


def _should_continue_on_error(config: Config) -> bool:
    """Check if we should continue on analysis errors."""
    return config.get("mode") != "block"


def _run_pip_install(packages: List[str]) -> None:
    """
    Run the actual pip install command.
    
    Args:
        packages: List of package names to install
    """
    console.print(f"[bold green]🚀 Installing packages: {', '.join(packages)}[/bold green]")
    
    # Build pip command
    pip_cmd = [sys.executable, "-m", "pip", "install"] + list(packages)
    
    try:
        # Run pip install and stream output
        result = subprocess.run(pip_cmd, check=True, capture_output=False)
        console.print("[green]✅ Installation completed successfully![/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ pip install failed with exit code {e.returncode}[/red]")
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        console.print("\\n[yellow]⏹️  Installation interrupted by user[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    main()
