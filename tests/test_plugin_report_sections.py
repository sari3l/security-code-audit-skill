import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import plugin_report_render  # noqa: E402
import report_gate_check  # noqa: E402
from audit_plugin_check import check_plugins  # noqa: E402
from test_audit_plugin_contract import make_skill_plugin  # noqa: E402


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


class PluginReportSectionTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        self.plugins_root = base / "plugins"
        self.plugins_root.mkdir()
        make_skill_plugin(self.plugins_root)
        self.run_dir = base / "state"
        self.run_dir.mkdir()
        (self.run_dir / "sample-context.json").write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        write_jsonl(
            self.run_dir / "sample-rows.jsonl",
            [
                {"fingerprint": "sca-low", "package": "minimist", "advisory_id": "GHSA-low", "scanner_severity": "LOW",
                 "advisory_url": "https://sca.test/vulns/GHSA-low", "disposition": None},
                {"fingerprint": "sca-high", "package": "lo|dash", "advisory_id": "GHSA-high", "scanner_severity": "HIGH",
                 "advisory_url": "https://sca.test/vulns/GHSA-high", "disposition": None},
            ],
        )
        write_jsonl(self.run_dir / "sample-review.jsonl", [{"fingerprint": "sca-high", "disposition": "not_reachable"}])
        self.plugins, issues = check_plugins(self.plugins_root)
        self.assertEqual([], [issue.to_dict() for issue in issues])

    def render(self) -> tuple[str, list]:
        issues: list = []
        return "\n".join(plugin_report_render.render_plugin_sections(self.plugins, self.run_dir, issues)), issues

    def test_plugin_rows_render_as_independent_table_with_review_merged(self) -> None:
        text, issues = self.render()
        self.assertEqual([], issues)
        self.assertIn("## Sample Results", text)
        self.assertIn("- **状态**: completed", text)
        self.assertIn("| 组件 | 编号 | 处置 |", text)
        lines = [line for line in text.splitlines() if line.startswith("| ") and "组件" not in line and "---" not in line]
        # Severity order puts HIGH first; pipe in remote data stays inside one cell.
        self.assertEqual("| lo\\|dash | [GHSA-high](https://sca.test/vulns/GHSA-high) | 不可达 |", lines[0])
        self.assertIn("待本地核对", lines[1])
        self.assertIn("共 2 条，已本地核对 1 条，待核对 1 条。", text)

    def test_plugin_without_context_artifact_is_not_reported(self) -> None:
        (self.run_dir / "sample-context.json").unlink()
        text, _ = self.render()
        self.assertEqual("", text)

    def test_report_gate_requires_plugin_section_and_every_row(self) -> None:
        text, _ = self.render()
        with patch.object(report_gate_check, "PLUGINS_ROOT", self.plugins_root):
            ok = report_gate_check._check_plugin_sections("# 报告\n\n" + text, self.run_dir)
            missing = report_gate_check._check_plugin_sections("# 报告\n\n## 已确认漏洞\n\n无。\n", self.run_dir)
            truncated = report_gate_check._check_plugin_sections(
                "\n".join(line for line in text.splitlines() if "minimist" not in line), self.run_dir
            )
        self.assertEqual([], [issue.to_dict() for issue in ok])
        self.assertEqual(["REPORT060"], [issue.code for issue in missing])
        self.assertEqual(["REPORT061"], [issue.code for issue in truncated])


if __name__ == "__main__":
    unittest.main()
