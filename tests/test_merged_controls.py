import json
from pathlib import Path
import tempfile
import unittest

from test_dangerous_capability_controls import StateFixture
from audit_state_check import check_state
from report_gate_check import check_report


REPORT = '## Confirmed Findings\n\n### [HIGH]-001: Confirmed issue\n- **Severity**: HIGH\n- **Maturity**: Confirmed\n- **Category / Surface**: Authorization\n- **Fingerprint**: authz-owner\n- **Location**: app.py:1\n- **Status**: New\n- **Description**: A concrete issue.\n- **Attack Vector**: Request input.\n- **Impact**: Data access.\n- **PoC**: bounded fixture\n- **Evidence**: source evidence\n- **Minimal Fix**: bind owner\n- **Hardening**: add regression\n- **Related Findings**: None\n- **Evidence Observation Refs**: ev-1\n'


def verification(**overrides):
    row = {
        "id": "verify-1", "candidate_fingerprint": "authz-owner",
        "stage": "final_record", "verifier_id": "reviewer",
        "independence": "fresh_pass", "decision": "confirmed",
        "source_rechecked": True, "local_check": "none",
        "evidence_refs": ["ev-1"], "blockers": [],
    }
    row.update(overrides)
    return row


class MergedControlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = Path(self.temp.name) / "target"
        self.state = Path(self.temp.name) / "state"
        self.target.mkdir()
        self.state.mkdir()
        (self.target / "safe.py").write_text("value = 1\n")
        StateFixture.initialize(self.state, self.target)

    def check_report(self, rows):
        StateFixture.write_jsonl(self.state / "verification-ledger.jsonl", rows)
        return check_report(REPORT, run_dir=self.state, target_root=self.target)

    def test_completed_final_verification_and_fresh_source_pass(self):
        self.assertEqual([], self.check_report([verification()]))

    def test_empty_or_unrelated_verification_does_not_confirm_finding(self):
        for rows in ([], [verification(candidate_fingerprint="another-issue")]):
            with self.subTest(rows=rows):
                codes = {issue.code for issue in self.check_report(rows)}
                self.assertIn("REPORT051", codes)

    def test_source_recheck_and_blocker_cannot_be_faked_by_confirmed_label(self):
        for overrides in ({"source_rechecked": False}, {"blockers": ["unresolved auth boundary"]}):
            with self.subTest(overrides=overrides):
                codes = {issue.code for issue in self.check_report([verification(**overrides)])}
                self.assertIn("STATE061", codes)
                self.assertIn("REPORT051", codes)

    def test_missing_exploration_record_blocks_completion(self):
        (self.state / "exploration-ledger.jsonl").unlink()
        codes = {issue.code for issue in check_state(self.state, target_root=self.target)}
        self.assertIn("STATE030", codes)

    def test_trace_requires_structured_entry_and_evidence(self):
        StateFixture.write_jsonl(self.state / "trace-ledger.jsonl", [{"id": "trace-1"}])
        codes = {issue.code for issue in check_state(self.state, target_root=self.target)}
        self.assertIn("STATE033", codes)
        self.assertIn("STATE035", codes)


if __name__ == "__main__":
    unittest.main()
