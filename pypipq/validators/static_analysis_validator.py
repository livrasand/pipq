# Copyright (C) 2025 Livrädo Sandoval
# Licensed under GPL-3.0

"""
Validator that performs static analysis on package source code and scans for malware.
"""
import os
import ast
import re
import mmap
import requests
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..core.base_validator import BaseValidator
from ..core.config import Config

class AstVisitor(ast.NodeVisitor):
    """
    An AST visitor that looks for suspicious patterns in Python code.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[Dict[str, Any]] = []
        self.suspicious_imports = {
            "subprocess", "ftplib", "http.client",
            "urllib", "requests", "telnetlib", "shutil"
        }
        self.suspicious_calls = {"eval", "exec"}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in self.suspicious_imports:
                self.findings.append({
                    "type": "Suspicious Import",
                    "value": alias.name,
                    "line": node.lineno
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in self.suspicious_imports:
            self.findings.append({
                "type": "Suspicious Import",
                "value": node.module,
                "line": node.lineno
            })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in self.suspicious_calls:
            self.findings.append({
                "type": "Suspicious Call",
                "value": node.func.id,
                "line": node.lineno
            })
        elif isinstance(node.func, ast.Attribute) and node.func.attr == 'system' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
             self.findings.append({
                "type": "Suspicious Call",
                "value": "os.system",
                "line": node.lineno
            })
        self.generic_visit(node)

class StaticAnalysisValidator(BaseValidator):
    """
    Performs static analysis on package source code to detect suspicious patterns
    and scans package files for malware using VirusTotal.
    """
    name = "Static Analysis"
    category = "Security"
    description = "Scans package for malware and suspicious code patterns."

    VIRUSTOTAL_API_URL_FILE_SCAN = "https://www.virustotal.com/vtapi/v2/file/scan"
    VIRUSTOTAL_API_URL_FILE_REPORT = "https://www.virustotal.com/vtapi/v2/file/report"

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, extracted_path: Optional[str] = None, downloaded_file_path: Optional[str] = None) -> None:
        super().__init__(pkg_name, metadata, config, extracted_path=extracted_path, downloaded_file_path=downloaded_file_path)
        self.virustotal_api_key = self.config.get("api_keys.virustotal")
        self.timeout = self.config.get("validators.StaticAnalysis.timeout", 120)

    def _validate(self) -> None:
        self._run_static_analysis()
        self._run_virustotal_scan()
        self._run_semgrep_scan()

    def _run_static_analysis(self) -> None:
        if not self.extracted_path:
            self.add_info("Static Analysis", "Skipped (package not extracted).")
            return

        analyzer = SafeStaticAnalyzer()
        findings = []
        for root, _, files in os.walk(self.extracted_path):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    # Try sandboxed analysis first, fallback to direct
                    file_findings = analyzer.analyze_in_sandbox(file_path)
                    if file_findings:
                        findings.extend(file_findings)
                    else:
                        # Fallback to the old method for large files or if sandbox fails
                        findings.extend(self._analyze_file(file_path))

        if findings:
            for finding in findings:
                message = f"{finding['type']}: '{finding['value']}' in {self.pkg_name} on line {finding['line']}"
                self.add_warning(message)


    def _analyze_file(self, file_path: str, max_size: int = 10*1024*1024) -> list:
        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            self.add_warning(f"File too large for analysis: {file_path}")
            return []

        try:
            # Use mmap for large files to avoid loading entire file into memory
            with open(file_path, 'r+b') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                    content = mmapped.read(max_size).decode('utf-8', errors='ignore')
                    tree = ast.parse(content, filename=file_path)
                    visitor = AstVisitor(file_path)
                    visitor.visit(tree)

                    if re.search(r"b64decode|base64.b64decode", content):
                        visitor.findings.append({"type": "Suspicious Content", "value": "base64", "line": "N/A"})

                    return visitor.findings
        except (SyntaxError, ValueError, OSError) as e:
            self.add_warning(f"Could not parse Python file {file_path}: {e}")
            return []

    def _run_virustotal_scan(self) -> None:
        if not self.virustotal_api_key:
            self.add_info("VirusTotal Scan", "Premium option: configure VIRUSTOTAL_API_KEY for malware scanning.")
            return

        if not self.downloaded_file_path:
            self.add_info("VirusTotal Scan", "Skipped (package file not downloaded).")
            return

        try:
            self._scan_file(Path(self.downloaded_file_path))
        except Exception as e:
            self.add_warning(f"Error during VirusTotal scan: {e}")

    def _scan_file(self, file_path: Path) -> None:
        params = {"apikey": self.virustotal_api_key}
        files = {"file": (file_path.name, open(file_path, "rb"))}

        response = requests.post(self.VIRUSTOTAL_API_URL_FILE_SCAN, files=files, params=params, timeout=self.timeout)
        response.raise_for_status()
        scan_result = response.json()

        resource = scan_result.get("resource")
        if resource:
            self._get_scan_report(resource)

    def _get_scan_report(self, resource: str) -> None:
        params = {"apikey": self.virustotal_api_key, "resource": resource}
        response = requests.get(self.VIRUSTOTAL_API_URL_FILE_REPORT, params=params, timeout=self.timeout)

        if response.status_code == 200:
            report = response.json()
            if report.get("response_code") == 1 and report.get("positives", 0) > 0:
                self.add_error(f"Malware Found (VirusTotal): {report.get('positives')} detections on {report.get('scan_date')}.")
            else:
                self.add_info("VirusTotal Scan", "No malware detected.")

    def _run_semgrep_scan(self) -> None:
        """Run Semgrep vulnerability scanning on the package."""
        if not self.extracted_path:
            self.add_info("Semgrep Scan", "Skipped (package not extracted).")
            return

        # Check if semgrep is available
        if not self._is_semgrep_available():
            self.add_info("Semgrep Scan", "Semgrep not available. Install semgrep for vulnerability scanning.")
            return

        try:
            # Run semgrep scan
            findings = self._run_semgrep_command()

            if findings:
                for finding in findings:
                    severity = finding.get("severity", "unknown")
                    rule = finding.get("check_id", "unknown")
                    file_path = finding.get("path", "unknown")
                    line = finding.get("line", "unknown")
                    message = finding.get("message", "Vulnerability detected")

                    warning_msg = f"Semgrep {severity}: {rule} in {file_path}:{line} - {message}"
                    if severity in ["error", "high"]:
                        self.add_error(warning_msg)
                    else:
                        self.add_warning(warning_msg)
            else:
                self.add_info("Semgrep Scan", "No vulnerabilities detected.")

        except Exception as e:
            self.add_warning(f"Error during Semgrep scan: {e}")

    def _is_semgrep_available(self) -> bool:
        """Check if semgrep command is available."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False

    def _run_semgrep_command(self) -> List[Dict[str, Any]]:
        """Run semgrep command and parse results."""
        try:
            # Run semgrep with JSON output
            cmd = [
                "semgrep",
                "--json",
                "--config", "auto",  # Use default rules
                "--quiet",
                self.extracted_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.extracted_path
            )

            if result.returncode in [0, 1]:  # 0 = no findings, 1 = findings found
                import json
                try:
                    output = json.loads(result.stdout)
                    return output.get("results", [])
                except json.JSONDecodeError:
                    # Try to parse stderr if stdout failed
                    try:
                        output = json.loads(result.stderr)
                        return output.get("results", [])
                    except json.JSONDecodeError:
                        return []
            else:
                # Semgrep failed
                return []

        except subprocess.TimeoutExpired:
            self.add_warning("Semgrep scan timed out")
            return []
        except Exception as e:
            self.add_warning(f"Failed to run semgrep: {e}")
            return []


class SafeStaticAnalyzer:
    """Static analyzer that uses sandboxing for safer analysis."""

    def analyze_in_sandbox(self, code_path: str) -> Optional[List[Dict[str, Any]]]:
        """Analyze code in a sandboxed environment."""
        try:
            # Try firejail first (Linux)
            result = subprocess.run([
                "firejail",
                "--quiet",
                "--net=none",
                "--read-only=" + code_path,
                "python", "-c", f"import ast; print(ast.dump(ast.parse(open('{code_path}').read())))"
            ], capture_output=True, timeout=10, text=True)

            if result.returncode == 0:
                # Parse the AST output
                return self._parse_ast_output(result.stdout)
            else:
                # Fallback to direct analysis if firejail fails
                return self._analyze_directly(code_path)

        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            # Fallback to direct analysis
            return self._analyze_directly(code_path)

    def _analyze_directly(self, code_path: str) -> Optional[List[Dict[str, Any]]]:
        """Direct analysis without sandboxing."""
        try:
            with open(code_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                tree = ast.parse(content, filename=code_path)
                visitor = AstVisitor(code_path)
                visitor.visit(tree)

                if re.search(r"b64decode|base64.b64decode", content):
                    visitor.findings.append({"type": "Suspicious Content", "value": "base64", "line": "N/A"})

                return visitor.findings
        except (SyntaxError, ValueError, OSError):
            return []

    def _parse_ast_output(self, ast_output: str) -> List[Dict[str, Any]]:
        """Parse AST dump output into findings."""
        # This is a simplified parser - in practice, you'd need more sophisticated parsing
        findings = []
        # For now, just return empty list as parsing AST dump is complex
        return findings
