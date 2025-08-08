
import os
import requests
import tempfile
import shutil
from pathlib import Path
from ..core.base_validator import BaseValidator
from typing import Dict, Any

class SandboxValidator(BaseValidator):
    """
    Validator that scans a package distribution file for malware using VirusTotal.

    This validator downloads the latest release files of a package into a temporary
    sandboxed directory, uploads them to VirusTotal, and analyzes the resulting report
    to detect known malware signatures. It flags the package if any detections are found.
    """

    name = "Sandbox"
    category = "Security"
    description = "Scans package files for malware using VirusTotal sandbox analysis"

    # VirusTotal API endpoints
    VIRUSTOTAL_API_URL_FILE_SCAN = "https://www.virustotal.com/vtapi/v2/file/scan"
    VIRUSTOTAL_API_URL_FILE_REPORT = "https://www.virustotal.com/vtapi/v2/file/report"

    def __init__(self, pkg_name: str, metadata: Dict[str, Any]):
        super().__init__(pkg_name, metadata)
        self.virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        self.timeout = 120  # Increased timeout for file uploads

    def _validate(self) -> None:
        if not self.virustotal_api_key:
            self.add_info("Malware Scan (Sandbox)", "Skipping sandbox scan: VIRUSTOTAL_API_KEY not set.")
            return

        releases = self.metadata.get("releases", {})
        latest_version = self.get_metadata_field("version")

        if latest_version in releases:
            for dist_file in releases[latest_version]:
                url = dist_file.get("url")
                if url:
                    self._download_and_scan(url)

    def _download_and_scan(self, url: str) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                file_path = self._download_file(url, temp_dir)
                if file_path:
                    self._scan_file(file_path)
            except Exception as e:
                self.add_warning(f"Error during sandbox scan: {e}")

    def _download_file(self, url: str, temp_dir: str) -> Path:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        file_path = Path(temp_dir) / Path(url).name
        with open(file_path, "wb") as f:
            shutil.copyfileobj(response.raw, f)
        return file_path

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
        response.raise_for_status()
        report = response.json()

        if report.get("response_code") == 1 and report.get("positives", 0) > 0:
            self.add_error(f"Malware Found (VirusTotal Sandbox): {report.get('positives')} detections.")
