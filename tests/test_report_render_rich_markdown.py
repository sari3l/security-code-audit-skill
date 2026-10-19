import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
REPORT_NAME = "security-code-audit-2026-07-07-120000-standard-abcdef12.md"


def run_tool(name, *args):
    return subprocess.run(
        [sys.executable, str(TOOLS / name), *map(str, args)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class ReportRenderTests(unittest.TestCase):
    def test_renderer_preserves_multiline_markdown_poc_evidence_chain_and_mermaid(self):
        finding = {
            "schema_version": "finding.v1",
            "run_id": "run-1",
            "fingerprint": "application:command-injection:lookup-shell",
            "severity": "High",
            "maturity": "Confirmed",
            "category_surface": "C1 Command Injection",
            "locations": ["app.py:11", "routes/lookup.py:44"],
            "status": "New",
            "title": "Command injection in lookup route",
            "description": "User controlled `host` reaches a shell command.",
            "attack_vector": "An unauthenticated caller appends shell metacharacters to `host`.",
            "impact": "Remote command execution in the web process.",
            "poc": {
                "language": "bash",
                "code": "curl 'https://target.test/lookup?host=example.com;id'\n# success signal: uid=",
            },
            "evidence": {
                "language": "python",
                "code": "cmd = f\"nslookup {host}\"\nsubprocess.check_output(cmd, shell=True)",
            },
            "evidence_chain": [
                "HTTP query parameter `host` enters `lookup()`.",
                "`host` is interpolated into `cmd` without shell escaping.",
                "`subprocess.check_output(..., shell=True)` executes attacker-controlled shell syntax.",
            ],
            "mermaid": "flowchart LR\n  A[HTTP host parameter] --> B[cmd string]\n  B --> C[shell=True subprocess]\n  C --> D[RCE]",
            "minimal_fix": {
                "language": "python",
                "code": "subprocess.check_output([\"nslookup\", host], shell=False)",
            },
            "hardening": "Validate `host` as a DNS name before invoking any resolver.",
            "related_findings": [],
            "evidence_refs": ["obs-cmdi"],
            "dangerous_capability_refs": ["danger-shell-command"],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "output"
            findings = output / "security-code-audit-2026-07-07-120000-standard-abcdef12-findings-input.jsonl"
            report = output / REPORT_NAME
            canonical_findings = output / "security-code-audit-2026-07-07-120000-standard-abcdef12-findings.jsonl"
            findings.parent.mkdir(parents=True)
            findings.write_text(json.dumps(finding) + "\n", encoding="utf-8")

            render = run_tool("report_render.py", findings, "--coverage", "Partial", "--out", report)

            self.assertEqual(render.returncode, 0, render.stderr)
            text = report.read_text(encoding="utf-8")
            self.assertTrue(canonical_findings.is_file())
            self.assertEqual(findings.read_text(encoding="utf-8"), canonical_findings.read_text(encoding="utf-8"))
            self.assertFalse((Path(temp_dir) / "findings.jsonl").exists())

        self.assertIn("# 代码安全审计报告", text)
        self.assertIn("覆盖状态: Partial", text)
        self.assertIn("## 已确认漏洞", text)
        self.assertIn("- **严重性**: 高", text)
        self.assertIn("- **PoC**:", text)
        self.assertIn("Audit Ref: `danger-shell-command`", text)
        self.assertIn("```bash\ncurl 'https://target.test/lookup?host=example.com;id'", text)
        self.assertIn("- **证据链**:", text)
        self.assertIn("  1. HTTP query parameter `host` enters `lookup()`.", text)
        self.assertIn("- **证据**:", text)
        self.assertIn("```python\ncmd = f\"nslookup {host}\"", text)
        self.assertIn("- **攻击流程**:", text)
        self.assertIn("```mermaid\nflowchart LR", text)
        self.assertIn("- **最小修复**:", text)
        self.assertIn("```python\nsubprocess.check_output([\"nslookup\", host], shell=False)", text)

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.md"
            report_path.write_text(text, encoding="utf-8")
            gate = run_tool("report_gate_check.py", report_path)
        self.assertEqual(gate.returncode, 0, gate.stdout)

    def test_renderer_requires_evidence_chain_for_confirmed_findings(self):
        finding = {
            "schema_version": "finding.v1",
            "run_id": "run-1",
            "fingerprint": "application:command-injection:lookup-shell",
            "severity": "High",
            "maturity": "Confirmed",
            "category_surface": "C1 Command Injection",
            "locations": ["app.py:11"],
            "status": "New",
            "title": "Command injection in lookup route",
            "description": "User controlled `host` reaches a shell command.",
            "attack_vector": "An unauthenticated caller appends shell metacharacters to `host`.",
            "impact": "Remote command execution in the web process.",
            "poc": {"language": "bash", "code": "curl 'https://target.test/lookup?host=example.com;id'"},
            "evidence": {"language": "python", "code": "subprocess.check_output(cmd, shell=True)"},
            "minimal_fix": {"language": "python", "code": "subprocess.check_output([\"nslookup\", host])"},
            "hardening": "Validate `host` as a DNS name.",
            "related_findings": [],
            "evidence_refs": ["obs-cmdi"],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "output"
            findings = output / "security-code-audit-2026-07-07-120001-standard-abcdef12-findings-input.jsonl"
            report = output / "security-code-audit-2026-07-07-120001-standard-abcdef12.md"
            findings.parent.mkdir(parents=True)
            findings.write_text(json.dumps(finding) + "\n", encoding="utf-8")

            render = run_tool("report_render.py", findings, "--coverage", "Partial", "--out", report)

        self.assertEqual(render.returncode, 1)
        payload = json.loads(render.stdout)
        self.assertTrue(any("evidence_chain" in issue["message"] for issue in payload["issues"]))

    def test_renderer_generates_mermaid_from_evidence_chain_when_no_override_is_present(self):
        finding = {
            "schema_version": "finding.v1",
            "run_id": "run-1",
            "fingerprint": "application:command-injection:lookup-shell",
            "severity": "High",
            "maturity": "Confirmed",
            "category_surface": "C1 Command Injection",
            "locations": ["app.py:11"],
            "status": "New",
            "title": "Command injection in lookup route",
            "description": "User controlled `host` reaches a shell command.",
            "attack_vector": "An unauthenticated caller appends shell metacharacters to `host`.",
            "impact": "Remote command execution in the web process.",
            "poc": {"language": "bash", "code": "curl 'https://target.test/lookup?host=example.com;id'"},
            "evidence": {"language": "python", "code": "subprocess.check_output(cmd, shell=True)"},
            "evidence_chain": [
                "HTTP query parameter `host`",
                "Command string interpolation",
                "`shell=True` subprocess sink",
                "Remote command execution",
            ],
            "minimal_fix": {"language": "python", "code": "subprocess.check_output([\"nslookup\", host])"},
            "hardening": "Validate `host` as a DNS name.",
            "related_findings": [],
            "evidence_refs": ["obs-cmdi"],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "output"
            findings = output / "security-code-audit-2026-07-07-120002-standard-abcdef12-findings-input.jsonl"
            report = output / "security-code-audit-2026-07-07-120002-standard-abcdef12.md"
            findings.parent.mkdir(parents=True)
            findings.write_text(json.dumps(finding) + "\n", encoding="utf-8")

            render = run_tool("report_render.py", findings, "--coverage", "Partial", "--out", report)

            self.assertEqual(render.returncode, 0, render.stderr)
            text = report.read_text(encoding="utf-8")

        self.assertIn("- **攻击流程**:", text)
        self.assertIn("```mermaid\nflowchart LR", text)
        self.assertIn('step1["HTTP query parameter `host`"] --> step2["Command string interpolation"]', text)
        self.assertIn('step3["`shell=True` subprocess sink"] --> step4["Remote command execution"]', text)

    def test_renderer_rejects_nonstandard_output_path(self):
        finding = {
            "schema_version": "finding.v1",
            "run_id": "run-1",
            "fingerprint": "application:command-injection:lookup-shell",
            "severity": "High",
            "maturity": "Confirmed",
            "category_surface": "C1 Command Injection",
            "locations": ["app.py:11"],
            "status": "New",
            "title": "Command injection in lookup route",
            "description": "User controlled `host` reaches a shell command.",
            "attack_vector": "An unauthenticated caller appends shell metacharacters to `host`.",
            "impact": "Remote command execution in the web process.",
            "poc": {"language": "bash", "code": "curl 'https://target.test/lookup?host=example.com;id'"},
            "evidence": {"language": "python", "code": "subprocess.check_output(cmd, shell=True)"},
            "evidence_chain": ["input", "sink", "impact"],
            "minimal_fix": {"language": "python", "code": "subprocess.check_output([\"nslookup\", host])"},
            "hardening": "Validate `host` as a DNS name.",
            "related_findings": [],
            "evidence_refs": ["obs-cmdi"],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            findings = Path(temp_dir) / "output" / "security-code-audit-2026-07-07-120003-standard-abcdef12-findings-input.jsonl"
            report = Path(temp_dir) / "report.md"
            findings.parent.mkdir(parents=True)
            findings.write_text(json.dumps(finding) + "\n", encoding="utf-8")

            render = run_tool("report_render.py", findings, "--coverage", "Partial", "--out", report)

        self.assertEqual(render.returncode, 1)
        payload = json.loads(render.stdout)
        self.assertTrue(any("output/security-code-audit-" in issue["message"] for issue in payload["issues"]))

    def test_renderer_refuses_to_overwrite_existing_report(self):
        finding = {
            "schema_version": "finding.v1",
            "run_id": "run-1",
            "fingerprint": "application:command-injection:lookup-shell",
            "severity": "High",
            "maturity": "Confirmed",
            "category_surface": "C1 Command Injection",
            "locations": ["app.py:11"],
            "status": "New",
            "title": "Command injection in lookup route",
            "description": "User controlled `host` reaches a shell command.",
            "attack_vector": "An unauthenticated caller appends shell metacharacters to `host`.",
            "impact": "Remote command execution in the web process.",
            "poc": {"language": "bash", "code": "curl 'https://target.test/lookup?host=example.com;id'"},
            "evidence": {"language": "python", "code": "subprocess.check_output(cmd, shell=True)"},
            "evidence_chain": ["input", "sink", "impact"],
            "minimal_fix": {"language": "python", "code": "subprocess.check_output([\"nslookup\", host])"},
            "hardening": "Validate `host` as a DNS name.",
            "related_findings": [],
            "evidence_refs": ["obs-cmdi"],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "output"
            findings = output / "security-code-audit-2026-07-07-120004-standard-abcdef12-findings-input.jsonl"
            report = output / "security-code-audit-2026-07-07-120004-standard-abcdef12.md"
            output.mkdir(parents=True)
            findings.write_text(json.dumps(finding) + "\n", encoding="utf-8")
            report.write_text("existing report\n", encoding="utf-8")

            render = run_tool("report_render.py", findings, "--coverage", "Partial", "--out", report)

            self.assertEqual(render.returncode, 1)
            self.assertEqual(report.read_text(encoding="utf-8"), "existing report\n")
        payload = json.loads(render.stdout)
        self.assertTrue(any("already exists" in issue["message"] for issue in payload["issues"]))


if __name__ == "__main__":
    unittest.main()
