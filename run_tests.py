#!/usr/bin/env python3
"""
Test runner script for pipq test suite.

This script provides convenient commands to run different types of tests.
"""

import subprocess
import sys
import argparse
from pathlib import Path


def run_command(cmd, description):
    """Run a command and return the result."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print('='*60)

    try:
        result = subprocess.run(cmd, check=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed with exit code {e.returncode}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Run pipq tests")
    parser.add_argument(
        "command",
        choices=["all", "unit", "integration", "e2e", "coverage", "performance", "lint"],
        default="all",
        nargs="?",
        help="Test command to run"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--fail-fast", "-x",
        action="store_true",
        help="Stop on first failure"
    )

    args = parser.parse_args()

    # Base pytest command
    base_cmd = [sys.executable, "-m", "pytest"]
    if args.verbose:
        base_cmd.append("-v")
    if args.fail_fast:
        base_cmd.append("-x")

    success = True

    if args.command in ["all", "unit"]:
        success &= run_command(
            base_cmd + ["tests/unit/"],
            "Unit Tests"
        )

    if args.command in ["all", "integration"]:
        success &= run_command(
            base_cmd + ["tests/integration/"],
            "Integration Tests"
        )

    if args.command in ["all", "e2e"]:
        success &= run_command(
            base_cmd + ["tests/e2e/"],
            "End-to-End Tests"
        )

    if args.command == "coverage":
        success &= run_command(
            [sys.executable, "-m", "pytest", "--cov=pypipq", "--cov-report=html", "--cov-report=term-missing"],
            "Coverage Tests"
        )

    if args.command == "performance":
        success &= run_command(
            base_cmd + ["tests/integration/test_performance.py"],
            "Performance Benchmarks"
        )

    if args.command == "lint":
        # Run flake8 and mypy if available
        try:
            success &= run_command(
                [sys.executable, "-m", "flake8", "pypipq/"],
                "Code Linting (flake8)"
            )
        except FileNotFoundError:
            print("⚠️  flake8 not found, skipping linting")

        try:
            success &= run_command(
                [sys.executable, "-m", "mypy", "pypipq/"],
                "Type Checking (mypy)"
            )
        except FileNotFoundError:
            print("⚠️  mypy not found, skipping type checking")

    if success:
        print(f"\n🎉 All {args.command} tests passed!")
        return 0
    else:
        print(f"\n💥 Some {args.command} tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())