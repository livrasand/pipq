import unittest
import tempfile
import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock

from pypipq.validators.integrity_validator import IntegrityValidator
from pypipq.core.config import Config

class TestIntegrityValidator(unittest.TestCase):

    def setUp(self):
        # A mock config object can be used if complex config access is needed
        # For now, a simple object or a real Config() is fine.
        self.config = Config()
        self.pkg_name = "test-package"

    def test_hash_mismatch(self):
        """Test that a hash mismatch is detected correctly."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(b"file content")
            tmp_file_path = tmp_file.name

        # Calculate the actual hash
        actual_hash = hashlib.sha256(b"file content").hexdigest()

        # Create metadata with a fake hash
        fake_hash = "0" * 64
        self.assertNotEqual(actual_hash, fake_hash)

        metadata = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [{
                    "filename": Path(tmp_file_path).name,
                    "url": "https://example.com/test-package-1.0.0.tar.gz",
                    "digests": {"sha256": fake_hash}
                }]
            }
        }

        validator = IntegrityValidator(
            self.pkg_name,
            metadata,
            self.config,
            downloaded_file_path=tmp_file_path
        )
        validator.validate()

        self.assertEqual(len(validator.errors), 1)
        self.assertIn("CRITICAL: Hash mismatch!", validator.errors[0])

        # Clean up the temp file
        os.remove(tmp_file_path)

    def test_hash_match(self):
        """Test that a matching hash passes validation."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(b"file content")
            tmp_file_path = tmp_file.name

        actual_hash = hashlib.sha256(b"file content").hexdigest()

        metadata = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [{
                    "filename": Path(tmp_file_path).name,
                    "url": "https://example.com/test-package-1.0.0.tar.gz",
                    "digests": {"sha256": actual_hash}
                }]
            }
        }

        validator = IntegrityValidator(
            self.pkg_name,
            metadata,
            self.config,
            downloaded_file_path=tmp_file_path
        )
        validator.validate()

        self.assertEqual(len(validator.errors), 0)

        os.remove(tmp_file_path)

if __name__ == '__main__':
    unittest.main()
