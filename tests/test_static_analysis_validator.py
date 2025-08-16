import unittest
import tempfile
import os
from unittest.mock import MagicMock

from pypipq.validators.static_analysis_validator import StaticAnalysisValidator
from pypipq.core.config import Config

class TestStaticAnalysisValidator(unittest.TestCase):

    def setUp(self):
        self.config = Config()
        self.config.set("api_keys.virustotal", None)
        self.pkg_name = "test-package"
        self.metadata = {"info": {"version": "1.0.0"}}

    def test_suspicious_code_detection(self):
        """Test that suspicious code patterns are detected."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            with open(os.path.join(tmp_dir, "malicious_code.py"), "w") as f:
                f.write("import os\n")
                f.write("os.system('echo hello')\n")
                f.write("eval('1+1')\n")

            validator = StaticAnalysisValidator(
                self.pkg_name,
                self.metadata,
                self.config,
                extracted_path=tmp_dir
            )
            validator.validate()

            self.assertEqual(len(validator.warnings), 3)

            warning_messages = "".join(validator.warnings)
            self.assertIn("Suspicious Import: 'os'", warning_messages)
            self.assertIn("Suspicious Call: 'os.system'", warning_messages)
            self.assertIn("Suspicious Call: 'eval'", warning_messages)

if __name__ == '__main__':
    unittest.main()
