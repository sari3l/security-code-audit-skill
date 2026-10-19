import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from audit_state_check import check_state  # noqa: E402
from dangerous_capability_seed import (  # noqa: E402
    SENTINEL_FAMILIES,
    records_digest,
    scan_tree,
    seed_tree,
    write_seed_state,
)
from report_gate_check import check_report  # noqa: E402
from vulnerability_benchmark import evaluate_case, run_benchmark  # noqa: E402


class DangerousCapabilitySeedTests(unittest.TestCase):
    def test_nonexistent_or_empty_target_cannot_report_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            missing = seed_tree(root / "missing")
            empty = seed_tree(root)

            self.assertEqual("failed", missing["status"])
            self.assertEqual("SEED001", missing["issues"][0]["code"])
            self.assertEqual("failed", empty["status"])
            self.assertEqual("SEED002", empty["issues"][0]["code"])

    def test_seeds_api_eval_fixed_flask_key_session_consumers_and_shell_source(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            (target / "app.py").write_text(
                """
from flask import request, session

app.secret_key = "panacea_secret_key"

def execute():
    body = request.get_json()
    task_name = body["task_name"]
    params = body["params"]
    eval(f"{task_name}(**{params})")
    session[task_name] = True
    return task_name in session
""".lstrip(),
                encoding="utf-8",
            )
            (target / "deploy.sh").write_text("#!/bin/sh\n. ./.env\n", encoding="utf-8")

            records = scan_tree(target)
            kinds = {(record["family"], record["kind"]) for record in records}

            self.assertIn(("dynamic_code_evaluation", "python_eval"), kinds)
            self.assertIn(("signing_material", "hardcoded_signing_key"), kinds)
            self.assertIn(("signed_state_consumer", "session_write"), kinds)
            self.assertIn(("signed_state_consumer", "session_membership_test"), kinds)
            self.assertIn(("shell_code_loading", "shell_source"), kinds)

    def test_seeds_aliases_shell_true_indirect_key_cjs_and_inline_ci(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            (target / "app.py").write_text(
                """
from builtins import eval as run_code
from flask import session as login_state
import subprocess as sp

PANACEA_KEY = "panacea_secret_key"
app.secret_key = PANACEA_KEY
run_code(expr)
sp.run(cmd, shell=True)
if user_name in login_state:
    pass
""".lstrip(),
                encoding="utf-8",
            )
            (target / "worker.cjs").write_text("eval(input)\n", encoding="utf-8")
            (target / "pipeline.yml").write_text("steps:\n  - run: source .env\n  - run: eval \"$TASK\"\n", encoding="utf-8")

            kinds = {(record["family"], record["kind"]) for record in scan_tree(target)}

            self.assertIn(("dynamic_code_evaluation", "python_eval"), kinds)
            self.assertIn(("shell_command_execution", "python_subprocess_shell_true"), kinds)
            self.assertIn(("signing_material", "hardcoded_signing_key"), kinds)
            self.assertIn(("signed_state_consumer", "session_membership_test"), kinds)
            self.assertIn(("shell_code_loading", "shell_source"), kinds)
            self.assertIn(("shell_code_loading", "shell_eval"), kinds)
            self.assertIn(("dynamic_code_evaluation", "javascript_eval"), kinds)

    def test_seeds_indirect_signing_binding_and_safe_negatives(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            (target / "safe.py").write_text(
                """
import ast
import os
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
value = ast.literal_eval(raw)
""".lstrip(),
                encoding="utf-8",
            )
            safe_kinds = {(row["family"], row["kind"]) for row in scan_tree(target)}
            self.assertNotIn(("dynamic_code_evaluation", "python_eval"), safe_kinds)
            self.assertIn(("signing_material", "indirect_signing_key_binding"), safe_kinds)

            (target / "fallback.py").write_text(
                'app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or "dev-secret"\n',
                encoding="utf-8",
            )
            kinds = {record["kind"] for record in scan_tree(target)}
            self.assertIn("hardcoded_signing_key_fallback", kinds)

    def test_python_parse_failure_blocks_complete_seed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            state = root / "state"
            target.mkdir()
            state.mkdir()
            (target / "legacy.py").write_text("print value\neval(expr)\n", encoding="utf-8")
            payload = seed_tree(target)
            self.assertEqual("failed", payload["status"])
            self.assertIn("SEED004", {issue["code"] for issue in payload["issues"]})
            self.assertIn("python_eval", {row["kind"] for row in payload["records"]})
            (state / "manifest.json").write_text(
                json.dumps({"schema_version": "2.0", "run_id": "run-1"}), encoding="utf-8"
            )
            write_seed_state(state, payload)
            summary = json.loads((state / "dangerous-capability-census.json").read_text(encoding="utf-8"))
            self.assertFalse(summary["census_completed"])
            self.assertTrue((state / "dangerous-capability-seed.jsonl").read_text(encoding="utf-8"))

    def test_seeds_common_non_python_execution_surfaces(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            (target / "Runner.java").write_text(
                'class Runner { void run(String cmd) { Runtime.getRuntime().exec(cmd); } }\n',
                encoding="utf-8",
            )
            (target / "task.php").write_text("<?php eval($input); ?>\n", encoding="utf-8")
            (target / "deploy.ps1").write_text("Invoke-Expression $command\n", encoding="utf-8")

            kinds = {(row["family"], row["kind"]) for row in scan_tree(target)}
            self.assertIn(("shell_command_execution", "generic_process_execution"), kinds)
            self.assertIn(("dynamic_code_evaluation", "generic_dynamic_evaluation"), kinds)
            self.assertIn(("dynamic_code_evaluation", "powershell_invoke_expression"), kinds)


class StateFixture:
    @staticmethod
    def initialize(run_dir: Path, target: Path, *, disposition="high_risk_alert"):
        manifest = {
            "schema_version": "2.0",
            "run_id": "run-1",
            "findings_path": "findings.jsonl",
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (run_dir / "current-change-context.json").write_text(
            json.dumps({"fresh_recon_completed": True}), encoding="utf-8"
        )
        (run_dir / "requirements-context.json").write_text(
            json.dumps(
                {
                    "schema_version": "requirements-context.v1",
                    "run_id": "run-1",
                    "status": "not_configured",
                    "phase": {
                        "architecture_recon_completed": True,
                        "change_recon_completed": True,
                        "queried_before_security_review": True,
                    },
                    "anchor_summary": {},
                    "query_plan": [],
                    "connector_statuses": [],
                    "query_log": [],
                    "documents": [],
                    "conflicts": [],
                    "handling": {
                        "source_trust": "untrusted_external_context",
                        "may_narrow_audit_scope": False,
                        "no_match_proves_no_requirement": False,
                        "credentials_stored": False,
                        "full_documents_stored": False,
                    },
                }
            ),
            encoding="utf-8",
        )
        (run_dir / "coverage-ledger.jsonl").write_text("", encoding="utf-8")
        payload = seed_tree(target)
        if payload["status"] != "ok":
            raise AssertionError(payload["issues"])
        write_seed_state(run_dir, payload)

        ledger = StateFixture.read_jsonl(run_dir / "dangerous-capabilities.jsonl")
        traces = []
        for row in ledger:
            trace_id = f"trace-{row['id']}"
            row["disposition"] = disposition
            row["source_reachability"] = "unknown"
            row["trace_refs"] = [trace_id]
            row["report_refs"] = [row["id"]]
            traces.append({"id": trace_id, "run_id": "run-1", "status": "open"})
        StateFixture.write_jsonl(run_dir / "dangerous-capabilities.jsonl", ledger)
        StateFixture.write_jsonl(run_dir / "trace-ledger.jsonl", traces)
        return ledger

    @staticmethod
    def read_jsonl(path: Path):
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    @staticmethod
    def write_jsonl(path: Path, rows):
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


class DangerousCapabilityStateTests(unittest.TestCase):
    def test_source_bound_reconciled_alert_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            run_dir = root / "state"
            target.mkdir()
            run_dir.mkdir()
            (target / "app.py").write_text("eval(expr)\n", encoding="utf-8")
            StateFixture.initialize(run_dir, target)
            self.assertEqual([], check_state(run_dir, target_root=target))

    def test_zero_census_cannot_hide_real_eval(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            run_dir = root / "state"
            target.mkdir()
            run_dir.mkdir()
            (target / "app.py").write_text("eval(expr)\n", encoding="utf-8")
            StateFixture.initialize(run_dir, target)
            (run_dir / "dangerous-capability-seed.jsonl").write_text("", encoding="utf-8")
            summary = json.loads((run_dir / "dangerous-capability-census.json").read_text(encoding="utf-8"))
            summary["discovered_total"] = 0
            summary["records_digest"] = records_digest([])
            summary["family_totals"] = {family: 0 for family in SENTINEL_FAMILIES}
            (run_dir / "dangerous-capability-census.json").write_text(json.dumps(summary), encoding="utf-8")

            codes = {issue.code for issue in check_state(run_dir, target_root=target)}
            self.assertIn("DANGER043", codes)
            self.assertIn("DANGER047", codes)

    def test_fake_evidence_and_trace_refs_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            run_dir = root / "state"
            target.mkdir()
            run_dir.mkdir()
            (target / "app.py").write_text("eval(expr)\n", encoding="utf-8")
            ledger = StateFixture.initialize(run_dir, target)
            ledger[0]["evidence_refs"] = ["does-not-exist"]
            ledger[0]["trace_refs"] = ["not-a-real-trace"]
            StateFixture.write_jsonl(run_dir / "dangerous-capabilities.jsonl", ledger)

            codes = {issue.code for issue in check_state(run_dir, target_root=target)}
            self.assertIn("DANGER051", codes)

    def test_stale_source_after_seed_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            run_dir = root / "state"
            target.mkdir()
            run_dir.mkdir()
            source = target / "app.py"
            source.write_text("eval(expr)\n", encoding="utf-8")
            StateFixture.initialize(run_dir, target)
            source.write_text("eval(expr)\nexec(code)\n", encoding="utf-8")

            codes = {issue.code for issue in check_state(run_dir, target_root=target)}
            self.assertIn("DANGER046", codes)
            self.assertIn("DANGER047", codes)

    def test_confirmed_finding_ref_must_resolve_in_current_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            run_dir = root / "state"
            target.mkdir()
            run_dir.mkdir()
            (target / "app.py").write_text("eval(expr)\n", encoding="utf-8")
            ledger = StateFixture.initialize(run_dir, target, disposition="confirmed_finding")
            ledger[0]["finding_refs"] = ["application:eval:rce"]
            StateFixture.write_jsonl(run_dir / "dangerous-capabilities.jsonl", ledger)
            StateFixture.write_jsonl(
                run_dir / "findings.jsonl",
                [{"schema_version": "finding.v1", "run_id": "run-1", "fingerprint": "application:eval:rce"}],
            )
            self.assertEqual([], check_state(run_dir, target_root=target))

            StateFixture.write_jsonl(
                run_dir / "findings.jsonl",
                [{"schema_version": "finding.v1", "run_id": "old-run", "fingerprint": "application:eval:rce"}],
            )
            codes = {issue.code for issue in check_state(run_dir, target_root=target)}
            self.assertIn("DANGER052", codes)

    def test_reachable_eval_cannot_be_negative_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            run_dir = root / "state"
            target.mkdir()
            run_dir.mkdir()
            (target / "app.py").write_text("eval(expr)\n", encoding="utf-8")
            ledger = StateFixture.initialize(run_dir, target, disposition="negative_closed")
            ledger[0]["source_reachability"] = "reachable"
            ledger[0]["negative_evidence"] = ["one payload remained quoted"]
            ledger[0]["report_refs"] = []
            StateFixture.write_jsonl(run_dir / "dangerous-capabilities.jsonl", ledger)

            codes = {issue.code for issue in check_state(run_dir, target_root=target)}
            self.assertIn("DANGER023", codes)


class DangerousCapabilityReportGateTests(unittest.TestCase):
    def test_report_requires_exact_audit_ref_anchor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            run_dir = root / "state"
            target.mkdir()
            run_dir.mkdir()
            (target / "app.py").write_text("eval(expr)\n", encoding="utf-8")
            ledger = StateFixture.initialize(run_dir, target)
            record_id = ledger[0]["id"]

            fake = f"# Audit\n\n## High-Risk Dangerous Capability Alerts\n\ntext mentions {record_id}\n"
            exact = f"# Audit\n\n## High-Risk Dangerous Capability Alerts\n\nAudit Ref: `{record_id}`\n"
            fake_codes = {issue.code for issue in check_report(fake, run_dir=run_dir, target_root=target)}
            exact_codes = {issue.code for issue in check_report(exact, run_dir=run_dir, target_root=target)}

            self.assertIn("REPORT044", fake_codes)
            self.assertNotIn("REPORT044", exact_codes)
            self.assertNotIn("DANGER051", exact_codes)


class VulnerabilityBenchmarkSentinelTests(unittest.TestCase):
    def test_sentinel_keyword_without_structural_anchors_fails(self):
        result = evaluate_case(
            "keyword-only",
            {
                "expected_signals": [
                    {"id": "eval", "needles": ["eval alert"], "sentinel_family": "dynamic_code_evaluation"}
                ]
            },
            Path("keyword-only.md"),
            "## Candidate Signals\n\neval alert\n",
        )
        self.assertEqual(0, result["expected_signals_found"])
        self.assertIn("BENCH011", {issue["code"] for issue in result["issues"]})

    def test_empty_benchmark_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "cases").mkdir()
            reports = root / "reports"
            reports.mkdir()
            payload = run_benchmark(root, reports_dir=reports)
            self.assertEqual("failed", payload["status"])
            self.assertIn("BENCH900", {issue["code"] for issue in payload["issues"]})

    def test_source_to_report_sentinel_families_require_full_recall(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case = root / "cases" / "sentinels"
            source = case / "source"
            reports = root / "reports"
            source.mkdir(parents=True)
            reports.mkdir()
            (source / "app.py").write_text(
                """
from flask import session
import subprocess
app.secret_key = "known"
eval(raw)
subprocess.run(cmd, shell=True)
session["user"] = True
""".lstrip(),
                encoding="utf-8",
            )
            (source / "deploy.sh").write_text("source .env\n", encoding="utf-8")
            expected_report = [
                {"id": "eval", "needles": ["api eval alert"], "sentinel_family": "dynamic_code_evaluation", "record_ref": "danger-eval", "location": "app.py:4", "source": "request.json", "sink": "eval", "trace": "trace-eval"},
                {"id": "source", "needles": ["source env alert"], "sentinel_family": "shell_code_loading", "record_ref": "danger-source", "location": "deploy.sh:1", "source": ".env", "sink": "shell source", "trace": "trace-source"},
                {"id": "flask", "needles": ["session forgery"], "sentinel_family": "signing_key_identity", "record_ref": "danger-flask-key", "location": "app.py:3", "source": "known signing key", "sink": "session identity check", "trace": "trace-session"},
            ]
            expected_discovery = [
                {"id": "d-eval", "family": "dynamic_code_evaluation", "kind": "python_eval", "path": "app.py"},
                {"id": "d-command", "family": "shell_command_execution", "kind": "python_subprocess_shell_true", "path": "app.py"},
                {"id": "d-source", "family": "shell_code_loading", "kind": "shell_source", "path": "deploy.sh"},
                {"id": "d-key", "family": "signing_material", "kind": "hardcoded_signing_key", "path": "app.py"},
                {"id": "d-session", "family": "signed_state_consumer", "kind": "session_write", "path": "app.py"},
            ]
            (case / "case.json").write_text(
                json.dumps({"type": "sentinel", "expected_signals": expected_report, "expected_discovery": expected_discovery}),
                encoding="utf-8",
            )
            (reports / "sentinels.md").write_text(
                """## Candidate Signals

### Eval
api eval alert danger-eval app.py:4 request.json eval trace-eval

### Shell
source env alert danger-source deploy.sh:1 .env shell source trace-source

### Flask
session forgery danger-flask-key app.py:3 known signing key session identity check trace-session
""",
                encoding="utf-8",
            )

            payload = run_benchmark(root, reports_dir=reports)
            self.assertEqual("ok", payload["status"], payload["issues"])
            self.assertEqual(1.0, payload["summary"]["discovery_recall"])
            for counts in payload["summary"]["discovery_families"].values():
                self.assertEqual(1.0, counts["recall"])

    def test_fabricated_report_cannot_replace_source_discovery(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case = root / "cases" / "fake"
            source = case / "source"
            reports = root / "reports"
            source.mkdir(parents=True)
            reports.mkdir()
            (source / "safe.py").write_text("value = 1\n", encoding="utf-8")
            (case / "case.json").write_text(
                json.dumps({"expected_discovery": [{"id": "missing", "family": "dynamic_code_evaluation", "kind": "python_eval"}]}),
                encoding="utf-8",
            )
            (reports / "fake.md").write_text("## Candidate Signals\n\n### Eval\neval\n", encoding="utf-8")
            payload = run_benchmark(root, reports_dir=reports)
            self.assertEqual("failed", payload["status"])
            self.assertIn("BENCH907", {issue["code"] for issue in payload["issues"]})


if __name__ == "__main__":
    unittest.main()
