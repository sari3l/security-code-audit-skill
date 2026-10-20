import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from audit_state_check import (  # noqa: E402
    _check_coverage_identity_duplicates,
    _check_coverage_row_identity,
    _check_verification_ledger,
)
from report_gate_check import check_report  # noqa: E402


class CoverageLedgerContractTests(unittest.TestCase):
    def test_valid_canonical_row_is_accepted(self):
        row = {
            "id": "unit-1",
            "coverage_id": "route::authz::api::access%20control",
            "canonical_refs": {
                "surface": "route",
                "boundary": "authz",
                "subsystem": "api",
                "attack_class": "access control",
            },
        }

        self.assertEqual([], _check_coverage_row_identity(row, "unit-1"))

    def test_mismatched_canonical_id_is_rejected(self):
        row = {
            "id": "unit-1",
            "coverage_id": "route::authz::api::wrong",
            "canonical_refs": {
                "surface": "route",
                "boundary": "authz",
                "subsystem": "api",
                "attack_class": "access control",
            },
        }

        issues = _check_coverage_row_identity(row, "unit-1")

        self.assertEqual(["STATE044"], [issue.code for issue in issues])

    def test_duplicate_canonical_ids_are_rejected(self):
        rows = [
            {"id": "unit-1", "coverage_id": "same"},
            {"id": "unit-2", "coverage_id": "same"},
        ]

        issues = _check_coverage_identity_duplicates(rows, "coverage-ledger.jsonl")

        self.assertEqual(["STATE045"], [issue.code for issue in issues])

    def test_verification_rows_require_freshness_and_decision_provenance(self):
        row = {
            "id": "verify-1",
            "candidate_fingerprint": "authz-owner",
            "stage": "final_record",
            "verifier_id": "validator-1",
            "independence": "unavailable",
            "decision": "confirmed",
            "source_rechecked": True,
            "local_check": "none",
            "evidence_refs": ["trace-1"],
            "blockers": [],
        }

        issues = _check_verification_ledger([row], "verification-ledger.jsonl")

        self.assertEqual(["STATE053"], [issue.code for issue in issues])

    def test_valid_verification_row_is_accepted(self):
        row = {
            "id": "verify-1",
            "candidate_fingerprint": "authz-owner",
            "stage": "candidate",
            "verifier_id": "validator-1",
            "independence": "fresh_agent",
            "decision": "needs_validation",
            "source_rechecked": True,
            "local_check": "sandbox_blocked",
            "evidence_refs": ["trace-1"],
            "blockers": ["sandbox unavailable"],
        }

        self.assertEqual([], _check_verification_ledger([row], "verification-ledger.jsonl"))

    def test_confirmed_report_requires_verification_ledger(self):
        from tempfile import TemporaryDirectory

        report = """## Confirmed Findings

### [HIGH]-001: Confirmed issue
- **Severity**: HIGH
- **Maturity**: Confirmed
- **Category / Surface**: Authorization
- **Fingerprint**: authz-owner
- **Location**: app.py:1
- **Status**: New
- **Description**: A concrete issue.
- **Attack Vector**: Request input.
- **Impact**: Data access.
- **PoC**: bounded fixture
- **Evidence**: source evidence
- **Minimal Fix**: bind owner
- **Hardening**: add regression
- **Related Findings**: None
- **Evidence Observation Refs**: ev-1
"""
        with TemporaryDirectory() as temp:
            issues = check_report(report, run_dir=Path(temp))

        self.assertIn("REPORT050", {issue.code for issue in issues})


if __name__ == "__main__":
    unittest.main()
