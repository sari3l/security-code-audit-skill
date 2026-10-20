import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from audit_state_check import check_remediation_session, check_requirements_context  # noqa: E402


def valid_context(*, status="not_configured"):
    context = {
        "schema_version": "requirements-context.v1",
        "run_id": "run-1",
        "status": status,
        "phase": {
            "architecture_recon_completed": True,
            "change_recon_completed": True,
            "queried_before_security_review": True,
        },
        "anchor_summary": {"explicit_ids": ["SEC-482"]},
        "query_plan": [{"query": "SEC-482", "source": "explicit_id"}],
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
    if status == "available":
        context["connector_statuses"] = [{"connector_id": "sample-requirements", "status": "available"}]
        context["documents"] = [
            {
                "id": "doc-482",
                "connector_id": "sample-requirements",
                "title": "SEC-482 refund approval",
                "url": "https://requirements.example.test/doc-482",
                "document_status": "approved",
                "confidence": "high",
                "matched_anchors": [{"family": "explicit_id", "value": "SEC-482"}],
                "verification_result": "validated",
                "verification_evidence_refs": ["trace-refund-approval"],
            }
        ]
    return context


class RequirementContextStateTests(unittest.TestCase):
    def check_payload(self, payload):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "requirements-context.json").write_text(json.dumps(payload), encoding="utf-8")
            return check_requirements_context(run_dir, run_id="run-1")

    def test_valid_not_configured_and_available_states_pass(self):
        self.assertEqual([], self.check_payload(valid_context()))
        self.assertEqual([], self.check_payload(valid_context(status="available")))

    def test_file_schema_run_and_phase_are_mandatory(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(
                {"REQCTX001"},
                {issue.code for issue in check_requirements_context(Path(temp), run_id="run-1")},
            )

        payload = valid_context()
        payload["schema_version"] = "requirements-context.v0"
        payload["run_id"] = "old-run"
        payload["phase"]["change_recon_completed"] = False
        codes = {issue.code for issue in self.check_payload(payload)}
        self.assertTrue({"REQCTX004", "REQCTX006", "REQCTX009"}.issubset(codes))

    def test_active_connector_statuses_must_be_unique_and_terminal(self):
        payload = valid_context(status="available")
        payload["connector_statuses"] = [
            {"connector_id": "sample-requirements", "status": "running"},
            {"connector_id": "sample-requirements", "status": "available"},
        ]
        codes = {issue.code for issue in self.check_payload(payload)}
        self.assertIn("REQCTX013", codes)
        self.assertIn("REQCTX014", codes)

        payload = valid_context()
        payload["status"] = "missing_auth"
        payload["connector_statuses"] = [{"connector_id": "sample-requirements", "status": "available"}]
        self.assertIn("REQCTX034", {issue.code for issue in self.check_payload(payload)})

    def test_privacy_flags_credentials_and_raw_payloads_are_rejected(self):
        payload = valid_context(status="available")
        payload["handling"]["may_narrow_audit_scope"] = True
        payload["connector_statuses"][0]["token"] = "top-secret-value"
        payload["documents"][0]["content"] = "Authorization: Bearer abcdefghijklmnop"
        codes = {issue.code for issue in self.check_payload(payload)}
        self.assertTrue({"REQCTX019", "REQCTX031", "REQCTX032", "REQCTX033"}.issubset(codes))

    def test_candidates_require_explicit_verification_and_current_evidence(self):
        payload = valid_context(status="available")
        payload["documents"][0]["verification_result"] = "accepted"
        payload["documents"][0]["verification_evidence_refs"] = []
        codes = {issue.code for issue in self.check_payload(payload)}
        self.assertIn("REQCTX025", codes)

        payload = copy.deepcopy(valid_context(status="available"))
        payload["documents"][0]["verification_evidence_refs"] = []
        codes = {issue.code for issue in self.check_payload(payload)}
        self.assertIn("REQCTX028", codes)


class RemediationSessionStateTests(unittest.TestCase):
    def check_payload(self, payload):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "run_id": "run-1",
                        "findings_path": "findings.jsonl",
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "findings.jsonl").write_text(
                json.dumps(
                    {
                        "schema_version": "finding.v1",
                        "run_id": "run-1",
                        "fingerprint": "finding-1",
                        "maturity": "Confirmed",
                        "minimal_fix": "Use the safe operation.",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            if payload is not None:
                (run_dir / "remediation-session.json").write_text(json.dumps(payload), encoding="utf-8")
            return check_remediation_session(run_dir, run_id="run-1")

    def check_payload_with_findings(self, payload, findings):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "run_id": "run-1",
                        "findings_path": "findings.jsonl",
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "findings.jsonl").write_text(
                "".join(json.dumps(finding) + "\n" for finding in findings),
                encoding="utf-8",
            )
            (run_dir / "remediation-session.json").write_text(json.dumps(payload), encoding="utf-8")
            return check_remediation_session(run_dir, run_id="run-1")

    def valid_session(self):
        return {
            "schema_version": "remediation-session.v1",
            "run_id": "run-1",
            "start_authorization": "auto-fix",
            "repository_root": "/repo",
            "source_branch": "main",
            "source_head": "abc123",
            "repair_branch": "security-code-audit/fix-run-1",
            "worktree": "/repo-security-fix-run-1",
            "selected_finding_refs": ["finding-1"],
            "review": {"status": "accepted", "diff_digest": "digest"},
            "final_acceptance": {
                "accepted": True,
                "reviewed_diff_digest": "digest",
                "receipt_sha256": "receipt-hash",
            },
            "integration": {"status": "merged", "commit": "def456", "merge": "fast_forward"},
        }

    def test_missing_session_is_optional_and_valid_session_passes(self):
        self.assertEqual([], self.check_payload(None))
        self.assertEqual([], self.check_payload(self.valid_session()))

    def test_unaccepted_session_cannot_claim_commit_or_merge(self):
        payload = self.valid_session()
        payload["review"]["status"] = "pending_user"
        payload["final_acceptance"] = {
            "accepted": False,
            "reviewed_diff_digest": None,
            "receipt_sha256": None,
        }
        codes = {issue.code for issue in self.check_payload(payload)}
        self.assertTrue({"REMED012", "REMED016"}.issubset(codes))

    def test_accepted_session_requires_digest_receipt_and_finding_refs(self):
        payload = self.valid_session()
        payload["selected_finding_refs"] = []
        payload["review"]["diff_digest"] = None
        payload["final_acceptance"]["reviewed_diff_digest"] = None
        payload["final_acceptance"]["receipt_sha256"] = None
        codes = {issue.code for issue in self.check_payload(payload)}
        self.assertTrue({"REMED010", "REMED014", "REMED015"}.issubset(codes))

    def test_reviewed_session_requires_current_confirmed_finding_with_minimal_fix(self):
        payload = self.valid_session()
        findings = [
            {
                "schema_version": "finding.v1",
                "run_id": "run-1",
                "fingerprint": "finding-1",
                "maturity": "Candidate",
                "minimal_fix": "Unproven repair.",
            }
        ]
        codes = {issue.code for issue in self.check_payload_with_findings(payload, findings)}
        self.assertIn("REMED022", codes)

        findings[0]["maturity"] = "Confirmed"
        findings[0]["minimal_fix"] = ""
        codes = {issue.code for issue in self.check_payload_with_findings(payload, findings)}
        self.assertIn("REMED023", codes)

        findings[0]["run_id"] = "old-run"
        codes = {issue.code for issue in self.check_payload_with_findings(payload, findings)}
        self.assertIn("REMED021", codes)

        payload["selected_finding_refs"] = ["missing-finding"]
        codes = {issue.code for issue in self.check_payload_with_findings(payload, findings)}
        self.assertIn("REMED020", codes)

    def test_reviewed_session_resolves_finding_id_and_fingerprint(self):
        payload = self.valid_session()
        findings = [
            {
                "schema_version": "finding.v1",
                "run_id": "run-1",
                "id": "finding-display-id",
                "fingerprint": "finding-1",
                "maturity": "Confirmed",
                "minimal_fix": "Use the safe operation.",
            }
        ]
        self.assertEqual([], self.check_payload_with_findings(payload, findings))

        payload["selected_finding_refs"] = ["finding-display-id"]
        self.assertEqual([], self.check_payload_with_findings(payload, findings))


if __name__ == "__main__":
    unittest.main()
