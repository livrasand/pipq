"""
Validator that performs static analysis on package source code and scans for malware.
"""
import os
import ast
import re
import requests
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
            "socket", "subprocess", "os", "ftplib", "http.client",
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

    def _run_static_analysis(self) -> None:
        if not self.extracted_path:
            self.add_info("Static Analysis", "Skipped (package not extracted).")
            return

        findings = []
        for root, _, files in os.walk(self.extracted_path):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    findings.extend(self._analyze_file(file_path))

        if findings:
            for finding in findings:
                message = f"{finding['type']}: '{finding['value']}' in {self.pkg_name} on line {finding['line']}"
                self.add_warning(message)


    def _analyze_file(self, file_path: str) -> list:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                tree = ast.parse(content, filename=file_path)
                visitor = AstVisitor(file_path)
                visitor.visit(tree)

                if re.search(r"b64decode|base64.b64decode", content):
                    visitor.findings.append({"type": "Suspicious Content", "value": "base64", "line": "N/A"})

                return visitor.findings
        except (SyntaxError, ValueError) as e:
            self.add_warning(f"Could not parse Python file {file_path}: {e}")
            return []

    def _run_virustotal_scan(self) -> None:
        if not self.virustotal_api_key:
            self.add_info("VirusTotal Scan", "Skipped: VIRUSTOTAL_API_KEY not set.")
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
