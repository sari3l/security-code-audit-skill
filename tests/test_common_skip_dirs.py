import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from security_audit_tools.common import SKIP_DIRS, iter_text_files  # noqa: E402


class CommonSkipDirsTests(unittest.TestCase):
    def test_assurance_walker_includes_shebang_and_deployment_script_names(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "entrypoint").write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            (root / "Procfile").write_text("web: ./entrypoint\n", encoding="utf-8")
            (root / "worker.service").write_text("[Service]\nExecStart=/app/entrypoint\n", encoding="utf-8")

            names = {path.name for path in iter_text_files(root)}
            self.assertEqual({"Procfile", "entrypoint", "worker.service"}, names)

    def test_report_output_directory_is_skipped_by_assurance_walkers(self):
        self.assertIn("output", SKIP_DIRS)
        self.assertNotIn(".security-code-audit-reports", SKIP_DIRS)
        self.assertIn(".security-code-audit-state", SKIP_DIRS)


if __name__ == "__main__":
    unittest.main()
