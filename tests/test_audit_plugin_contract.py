import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from audit_plugin_check import check_plugins  # noqa: E402


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def skill_manifest(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": "1.0",
        "id": "sample",
        "displayName": "Sample Plugin",
        "enabled": True,
        "capabilities": ["sample-check"],
        "entrypoints": {"skills": ["./skills/sample/SKILL.md"]},
        "config": "./config.json",
        "report": {
            "heading": "Sample Results",
            "guide": "./README.md",
            "context": "sample-context.json",
            "rows": "sample-rows.jsonl",
            "review": "sample-review.jsonl",
            "rowKey": "fingerprint",
            "summary": [{"field": "status", "label": "状态"}],
            "columns": [
                {"field": "package", "label": "组件"},
                {"field": "advisory_id", "label": "编号", "link": "advisory_url"},
                {"field": "disposition", "label": "处置"},
            ],
        },
        "lifecycle": {
            "after": "audit-start",
            "before": "coverage-verification",
            "failure": "continue",
        },
    }
    payload.update(overrides)
    return payload


def make_skill_plugin(root: Path, manifest: dict[str, object] | None = None) -> Path:
    plugin = root / "sample"
    write_json(plugin / "plugin.json", manifest or skill_manifest())
    write_json(plugin / "config.json", {})
    (plugin / "README.md").write_text("# Sample Plugin\n", encoding="utf-8")
    skill = plugin / "skills" / "sample" / "SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text("---\nname: sample\ndescription: Sample audit plugin.\n---\n\nRun sample checks.\n", encoding="utf-8")
    return plugin


class AuditPluginContractTests(unittest.TestCase):
    def test_bundled_plugin_registry_is_valid(self) -> None:
        _, issues = check_plugins(ROOT / "plugins")
        self.assertEqual([], [issue.to_dict() for issue in issues])

    def test_framework_supports_no_bundled_providers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugins, issues = check_plugins(Path(temp_dir))
        self.assertEqual([], plugins)
        self.assertEqual([], issues)

    def test_skill_only_plugin_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            make_skill_plugin(root)
            plugins, issues = check_plugins(root)
        self.assertEqual([], [issue.to_dict() for issue in issues])
        self.assertEqual(["sample"], [plugin["id"] for plugin in plugins])

    def test_entrypoint_cannot_escape_plugin_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plugin = make_skill_plugin(
                root,
                skill_manifest(entrypoints={"skills": ["./../outside/SKILL.md"]}),
            )
            outside = root / "outside" / "SKILL.md"
            outside.parent.mkdir(parents=True)
            outside.write_text("outside", encoding="utf-8")
            _, issues = check_plugins(root)
        self.assertTrue(any(issue.code == "PLUGIN012" for issue in issues))
        self.assertEqual(plugin.name, "sample")

    def test_lifecycle_after_must_precede_before(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            make_skill_plugin(
                root,
                skill_manifest(
                    lifecycle={
                        "after": "report-finalization",
                        "before": "security-semantic-review",
                        "failure": "continue",
                    }
                ),
            )
            _, issues = check_plugins(root)
        self.assertTrue(any(issue.code == "PLUGIN030" for issue in issues))

    def test_config_rejects_inline_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plugin = make_skill_plugin(root)
            write_json(plugin / "config.json", {"token": "top-secret"})
            _, issues = check_plugins(root)
        self.assertTrue(any(issue.code == "PLUGIN026" for issue in issues))

    def test_plugin_requires_a_non_empty_readme(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plugin = make_skill_plugin(root)
            (plugin / "README.md").unlink()
            _, missing_issues = check_plugins(root)
            (plugin / "README.md").write_text("\n", encoding="utf-8")
            _, empty_issues = check_plugins(root)
        self.assertTrue(any(issue.code == "PLUGIN032" for issue in missing_issues))
        self.assertTrue(any(issue.code == "PLUGIN033" for issue in empty_issues))

    def test_plugin_must_declare_report_presentation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = skill_manifest()
            del manifest["report"]
            make_skill_plugin(root, manifest)
            _, issues = check_plugins(root)
        self.assertTrue(any(issue.code == "PLUGIN040" for issue in issues))

    def test_report_rows_require_columns_and_state_local_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = skill_manifest()
            manifest["report"] = {
                "heading": "Sample",
                "guide": "./README.md",
                "context": "../outside.json",
                "rows": "sample-rows.jsonl",
                "rowKey": "fingerprint",
            }
            make_skill_plugin(root, manifest)
            _, issues = check_plugins(root)
        codes = {issue.code for issue in issues}
        self.assertIn("PLUGIN043", codes)
        self.assertIn("PLUGIN044", codes)

    def test_mcp_config_environment_variables_must_be_forwarded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plugin = make_skill_plugin(
                root,
                skill_manifest(entrypoints={"mcp": "./.mcp.json"}),
            )
            write_json(
                plugin / "config.json",
                {"configEnv": "SAMPLE_CONFIG", "tokenEnv": "SAMPLE_TOKEN"},
            )
            write_json(
                plugin / ".mcp.json",
                {"mcpServers": {"sample": {"command": "node", "env_vars": ["SAMPLE_TOKEN"]}}},
            )
            write_json(
                plugin / ".codex-plugin" / "plugin.json",
                {"name": "sample", "mcpServers": "./.mcp.json"},
            )
            _, issues = check_plugins(root)
        self.assertTrue(
            any(
                issue.code == "PLUGIN034" and "SAMPLE_CONFIG" in issue.message
                for issue in issues
            )
        )
        self.assertFalse(
            any(
                issue.code == "PLUGIN034" and "SAMPLE_TOKEN" in issue.message
                for issue in issues
            )
        )


if __name__ == "__main__":
    unittest.main()
