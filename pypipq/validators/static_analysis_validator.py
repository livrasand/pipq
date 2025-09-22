"""Performs static analysis on source code and scans files for malware.

This validator combines two main security checks:
1.  **Static Code Analysis**: It walks the Abstract Syntax Tree (AST) of Python
    source files to find suspicious patterns, such as the use of `eval()`,
    `exec()`, or imports of modules commonly used for malicious activities
    (e.g., `socket`, `subprocess`).
2.  **Malware Scanning**: It integrates with the VirusTotal API to scan the
    downloaded package file for known malware signatures.
"""
import os
import ast
import re
import mmap
import requests
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..core.base_validator import BaseValidator
from ..core.config import Config


class AstVisitor(ast.NodeVisitor):
    """An AST visitor that identifies suspicious patterns in Python code.

    This visitor traverses the AST of a Python file and records findings
    related to potentially dangerous imports and function calls.

    Attributes:
        findings (List[Dict[str, Any]]): A list of suspicious patterns found.
    """
    def __init__(self):
        """Initializes the AstVisitor."""
        self.findings: List[Dict[str, Any]] = []
        self.suspicious_imports = {
            "socket", "subprocess", "os", "ftplib", "http.client",
            "urllib", "requests", "telnetlib", "shutil"
        }
        self.suspicious_calls = {"eval", "exec"}

    def visit_Import(self, node: ast.Import) -> None:
        """Visits `import` statements."""
        for alias in node.names:
            if alias.name in self.suspicious_imports:
                self.findings.append({
                    "type": "Suspicious Import", "value": alias.name, "line": node.lineno
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visits `from ... import` statements."""
        if node.module and node.module in self.suspicious_imports:
            self.findings.append({
                "type": "Suspicious Import", "value": node.module, "line": node.lineno
            })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Visits function call nodes."""
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Attempt to reconstruct the full call name, e.g., 'os.system'
            try:
                # This is a best-effort reconstruction.
                value = node.func.value
                parts = [node.func.attr]
                while isinstance(value, ast.Attribute):
                    parts.append(value.attr)
                    value = value.value
                if isinstance(value, ast.Name):
                    parts.append(value.id)
                    func_name = ".".join(reversed(parts))
            except AttributeError:
                pass

        if func_name in self.suspicious_calls or func_name == "os.system":
            self.findings.append({
                "type": "Suspicious Call", "value": func_name, "line": node.lineno
            })
        self.generic_visit(node)


class StaticAnalysisValidator(BaseValidator):
    """Performs static analysis on source code and scans files with VirusTotal."""
    name = "StaticAnalysis"
    category = "Security"
    description = "Scans package for malware and suspicious code patterns."

    VT_API_FILE_SCAN = "https://www.virustotal.com/vtapi/v2/file/scan"
    VT_API_FILE_REPORT = "https://www.virustotal.com/vtapi/v2/file/report"

    def __init__(self, pkg_name: str, metadata: Dict[str, Any], config: Config, **kwargs) -> None:
        """Initializes the StaticAnalysisValidator."""
        super().__init__(pkg_name, metadata, config, **kwargs)
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY") or self.config.get("api_keys.virustotal")
        self.timeout = self.config.get("validators.StaticAnalysis.timeout", 120)

    def _validate(self) -> None:
        """Runs the static analysis and VirusTotal scan."""
        self._run_code_analysis()
        self._run_virustotal_scan()

    def _run_code_analysis(self) -> None:
        """Walks through extracted files and performs static analysis."""
        if not self.extracted_path:
            self.add_info("Static Code Analysis", "Skipped because the package was not extracted.")
            return

        for root, _, files in os.walk(self.extracted_path):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    findings = self._analyze_file(file_path)
                    for finding in findings:
                        message = f"{finding['type']}: '{finding['value']}' found in '{Path(file_path).name}' on line {finding['line']}."
                        self.add_warning(message)

    def _analyze_file(self, file_path: str, max_size: int = 10 * 1024 * 1024) -> List[Dict[str, Any]]:
        """Analyzes a single Python file for suspicious patterns.

        Args:
            file_path (str): The path to the Python file.
            max_size (int): The maximum file size to analyze.

        Returns:
            List[Dict[str, Any]]: A list of findings from the analysis.
        """
        try:
            if os.path.getsize(file_path) > max_size:
                self.add_warning(f"File exceeds size limit for analysis: {file_path}")
                return []

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                tree = ast.parse(content, filename=file_path)
                visitor = AstVisitor()
                visitor.visit(tree)
                return visitor.findings
        except (SyntaxError, ValueError, OSError) as e:
            self.add_warning(f"Could not parse Python file {file_path}: {e}")
            return []

    def _run_virustotal_scan(self) -> None:
        """Initiates a file scan with the VirusTotal API."""
        if not self.virustotal_api_key:
            self.add_info("VirusTotal Scan", "Skipped: VIRUSTOTAL_API_KEY is not configured.")
            return
        if not self.downloaded_file_path:
            self.add_info("VirusTotal Scan", "Skipped because the package file was not downloaded.")
            return

        try:
            self._scan_file(Path(self.downloaded_file_path))
        except requests.RequestException as e:
            self.add_warning(f"Could not connect to VirusTotal API: {e}")
        except Exception as e:
            self.add_warning(f"An unexpected error occurred during VirusTotal scan: {e}")

    def _scan_file(self, file_path: Path) -> None:
        """Submits a file to VirusTotal for scanning.

        Args:
            file_path (Path): The path to the file to be scanned.
        """
        params = {"apikey": self.virustotal_api_key}
        with open(file_path, "rb") as f:
            files = {"file": (file_path.name, f)}
            response = requests.post(self.VT_API_FILE_SCAN, files=files, params=params, timeout=self.timeout)
        response.raise_for_status()
        scan_result = response.json()

        resource = scan_result.get("resource")
        if resource:
            self._get_scan_report(resource)
        else:
            self.add_warning(f"VirusTotal did not return a resource for scan ID: {scan_result.get('scan_id')}")

    def _get_scan_report(self, resource: str) -> None:
        """Retrieves a scan report from VirusTotal.

        Args:
            resource (str): The resource identifier for the scan report.
        """
        params = {"apikey": self.virustotal_api_key, "resource": resource}
        response = requests.get(self.VT_API_FILE_REPORT, params=params, timeout=self.timeout)
        response.raise_for_status()

        report = response.json()
        if report.get("response_code") == 1:  # Report is available
            positives = report.get("positives", 0)
            if positives > 0:
                self.add_error(
                    f"Malware detected by VirusTotal. {positives} out of {report.get('total', 0)} "
                    f"scanners flagged the file as malicious. Scan date: {report.get('scan_date')}."
                )
            else:
                self.add_info("VirusTotal Scan", "No malware detected.")
        else:
            self.add_info("VirusTotal Scan", "Scan report is not yet available. It may be queued for analysis.")
