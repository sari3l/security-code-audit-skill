import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "remediation_worktree.py"


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def initialize_repository(parent: Path) -> Path:
    repository = parent / "sample-project"
    repository.mkdir()
    git(repository, "init", "-b", "main")
    git(repository, "config", "user.email", "audit@example.test")
    git(repository, "config", "user.name", "Audit Test")
    (repository / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repository / ".gitignore").write_text("output/\n", encoding="utf-8")
    git(repository, "add", ".")
    git(repository, "commit", "-m", "initial")
    return repository


class RemediationWorktreeTests(unittest.TestCase):
    def run_helper(self, repository: Path, run_id: str = "run-123"):
        session = repository / "output" / "state" / "remediation-session.json"
        result = subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "create",
                str(repository),
                "--run-id",
                run_id,
                "--session-file",
                str(session),
                "--authorization",
                "auto-fix",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            state_dir = session.parent
            findings = state_dir / "findings.jsonl"
            (state_dir / "manifest.json").write_text(
                json.dumps({"schema_version": "2.0", "run_id": run_id, "findings_path": "findings.jsonl"}),
                encoding="utf-8",
            )
            findings.write_text(
                json.dumps(
                    {
                        "schema_version": "finding.v1",
                        "run_id": run_id,
                        "fingerprint": "finding-1",
                        "maturity": "Confirmed",
                        "minimal_fix": "Set VALUE to the safe value.",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
        return result

    def command(self, *args: str):
        return subprocess.run(
            ["python3", str(SCRIPT), *args],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_creates_isolated_branch_at_current_head_without_commit_or_merge(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            source_head = git(repository, "rev-parse", "HEAD")

            result = self.run_helper(repository)

            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            worktree = Path(payload["worktree"])
            self.assertTrue(worktree.is_dir())
            self.assertEqual("main", payload["source_branch"])
            self.assertEqual(source_head, payload["source_head"])
            self.assertEqual("security-code-audit/fix-run-123", payload["repair_branch"])
            self.assertEqual(source_head, git(worktree, "rev-parse", "HEAD"))
            self.assertEqual("main", git(repository, "branch", "--show-current"))
            self.assertTrue((repository / "output" / "state" / "remediation-session.json").is_file())
            self.assertFalse(payload["final_acceptance"]["accepted"])

    def test_dirty_source_is_blocked_and_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            (repository / "app.py").write_text("USER_CHANGE = True\n", encoding="utf-8")

            result = self.run_helper(repository)

            self.assertEqual(2, result.returncode)
            payload = json.loads(result.stdout)
            self.assertEqual("blocked", payload["status"])
            self.assertIn("not clean", payload["error"])
            self.assertEqual("USER_CHANGE = True\n", (repository / "app.py").read_text(encoding="utf-8"))
            self.assertNotIn("security-code-audit/fix-run-123", git(repository, "branch", "--list"))

    def test_existing_repair_branch_is_not_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            git(repository, "branch", "security-code-audit/fix-run-123")

            result = self.run_helper(repository)

            self.assertEqual(2, result.returncode)
            self.assertIn("already exists", json.loads(result.stdout)["error"])

    def test_requires_acceptance_and_merges_only_the_reviewed_diff(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            source_head = git(repository, "rev-parse", "HEAD")
            created = json.loads(self.run_helper(repository).stdout)
            worktree = Path(created["worktree"])
            session = repository / "output" / "state" / "remediation-session.json"
            (worktree / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

            snapshot = self.command(
                "snapshot",
                str(session),
                "--message",
                "fix: close audit finding",
                "--finding-ref",
                "finding-1",
                "--validation-summary",
                "unit tests passed",
                "--reaudit-summary",
                "original exploit path closed",
            )
            self.assertEqual(0, snapshot.returncode, snapshot.stdout)
            snapshotted = json.loads(snapshot.stdout)
            digest = snapshotted["review"]["diff_digest"]

            blocked = self.command("integrate", str(session), "--integration-receipt", "not-accepted")
            self.assertEqual(2, blocked.returncode)
            self.assertIn("final acceptance", json.loads(blocked.stdout)["error"])
            self.assertEqual(source_head, git(repository, "rev-parse", "HEAD"))

            accepted = self.command("accept", str(session), "--reviewed-digest", digest)
            self.assertEqual(0, accepted.returncode, accepted.stdout)
            acceptance = json.loads(accepted.stdout)
            integrated = self.command(
                "integrate",
                str(session),
                "--integration-receipt",
                acceptance["integration_receipt"],
            )
            self.assertEqual(0, integrated.returncode, integrated.stdout)
            integrated_payload = json.loads(integrated.stdout)
            self.assertEqual("merged", integrated_payload["status"])
            self.assertNotEqual(source_head, git(repository, "rev-parse", "HEAD"))
            self.assertEqual("VALUE = 2\n", (repository / "app.py").read_text(encoding="utf-8"))
            self.assertEqual("fix: close audit finding", git(repository, "log", "-1", "--format=%s"))

    def test_diff_change_after_snapshot_requires_new_review(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            created = json.loads(self.run_helper(repository).stdout)
            worktree = Path(created["worktree"])
            session = repository / "output" / "state" / "remediation-session.json"
            (worktree / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            snapshot = json.loads(
                self.command(
                    "snapshot",
                    str(session),
                    "--message",
                    "fix: close audit finding",
                    "--finding-ref",
                    "finding-1",
                ).stdout
            )
            (worktree / "app.py").write_text("VALUE = 3\n", encoding="utf-8")

            accepted = self.command(
                "accept",
                str(session),
                "--reviewed-digest",
                snapshot["review"]["diff_digest"],
            )

            self.assertEqual(2, accepted.returncode)
            self.assertIn("changed after review", json.loads(accepted.stdout)["error"])
            self.assertEqual("VALUE = 1\n", (repository / "app.py").read_text(encoding="utf-8"))

    def test_untracked_executable_mode_change_requires_new_review(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            created = json.loads(self.run_helper(repository).stdout)
            worktree = Path(created["worktree"])
            session = repository / "output" / "state" / "remediation-session.json"
            new_file = worktree / "safe-tool.sh"
            new_file.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            new_file.chmod(0o644)
            snapshot = json.loads(
                self.command(
                    "snapshot",
                    str(session),
                    "--message",
                    "fix: add safe helper",
                    "--finding-ref",
                    "finding-1",
                ).stdout
            )
            new_file.chmod(0o755)

            accepted = self.command(
                "accept",
                str(session),
                "--reviewed-digest",
                snapshot["review"]["diff_digest"],
            )

            self.assertEqual(2, accepted.returncode)
            self.assertIn("changed after review", json.loads(accepted.stdout)["error"])
            self.assertFalse((repository / "safe-tool.sh").exists())

    def test_original_head_drift_blocks_commit_and_merge(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            created = json.loads(self.run_helper(repository).stdout)
            worktree = Path(created["worktree"])
            session = repository / "output" / "state" / "remediation-session.json"
            (worktree / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            snapshot = json.loads(
                self.command(
                    "snapshot",
                    str(session),
                    "--message",
                    "fix: close audit finding",
                    "--finding-ref",
                    "finding-1",
                ).stdout
            )
            accepted = self.command(
                "accept",
                str(session),
                "--reviewed-digest",
                snapshot["review"]["diff_digest"],
            )
            self.assertEqual(0, accepted.returncode, accepted.stdout)
            receipt = json.loads(accepted.stdout)["integration_receipt"]
            (repository / "other.py").write_text("OTHER = True\n", encoding="utf-8")
            git(repository, "add", "other.py")
            git(repository, "commit", "-m", "concurrent source change")
            drift_head = git(repository, "rev-parse", "HEAD")

            integrated = self.command(
                "integrate",
                str(session),
                "--integration-receipt",
                receipt,
            )

            self.assertEqual(2, integrated.returncode)
            self.assertIn("HEAD changed", json.loads(integrated.stdout)["error"])
            self.assertEqual(drift_head, git(repository, "rev-parse", "HEAD"))
            self.assertEqual(created["source_head"], git(worktree, "rev-parse", "HEAD"))

    def test_persisted_acceptance_without_current_receipt_cannot_integrate(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            created = json.loads(self.run_helper(repository).stdout)
            worktree = Path(created["worktree"])
            session = repository / "output" / "state" / "remediation-session.json"
            (worktree / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            snapshot = json.loads(
                self.command(
                    "snapshot",
                    str(session),
                    "--message",
                    "fix: close audit finding",
                    "--finding-ref",
                    "finding-1",
                ).stdout
            )
            accepted = self.command(
                "accept",
                str(session),
                "--reviewed-digest",
                snapshot["review"]["diff_digest"],
            )
            self.assertEqual(0, accepted.returncode, accepted.stdout)

            integrated = self.command(
                "integrate",
                str(session),
                "--integration-receipt",
                "forged-or-stale-receipt",
            )

            self.assertEqual(2, integrated.returncode)
            self.assertIn("current-turn integration receipt", json.loads(integrated.stdout)["error"])
            self.assertEqual(created["source_head"], git(repository, "rev-parse", "HEAD"))

    def test_generated_audit_output_is_not_eligible_for_repair_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            created = json.loads(self.run_helper(repository).stdout)
            worktree = Path(created["worktree"])
            session = repository / "output" / "state" / "remediation-session.json"
            (worktree / "output").mkdir()
            (worktree / "output" / "report.md").write_text("audit report\n", encoding="utf-8")

            snapshot = self.command(
                "snapshot",
                str(session),
                "--message",
                "fix: invalid output",
                "--finding-ref",
                "finding-1",
            )

            self.assertEqual(2, snapshot.returncode)
            self.assertIn("no changes", json.loads(snapshot.stdout)["error"])

    def test_custom_git_filter_blocks_integration(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            (repository / ".gitattributes").write_text("app.py filter=unsafe\n", encoding="utf-8")
            git(repository, "add", ".gitattributes")
            git(repository, "commit", "-m", "configure repository filter")
            created = self.run_helper(repository)

            self.assertEqual(2, created.returncode)
            self.assertIn("custom Git filter", json.loads(created.stdout)["error"])
            self.assertNotIn("security-code-audit/fix-run-123", git(repository, "branch", "--list"))

    def test_snapshot_rejects_non_confirmed_or_unknown_finding_refs(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            created = json.loads(self.run_helper(repository).stdout)
            worktree = Path(created["worktree"])
            session = repository / "output" / "state" / "remediation-session.json"
            findings = session.parent / "findings.jsonl"
            findings.write_text(
                json.dumps(
                    {
                        "schema_version": "finding.v1",
                        "run_id": "run-123",
                        "fingerprint": "candidate-1",
                        "maturity": "Candidate",
                        "minimal_fix": "Unproven change",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (worktree / "app.py").write_text("VALUE = 2\n", encoding="utf-8")

            candidate = self.command(
                "snapshot",
                str(session),
                "--message",
                "fix: candidate",
                "--finding-ref",
                "candidate-1",
            )
            unknown = self.command(
                "snapshot",
                str(session),
                "--message",
                "fix: unknown",
                "--finding-ref",
                "missing-1",
            )

            self.assertEqual(2, candidate.returncode)
            self.assertIn("Confirmed finding", json.loads(candidate.stdout)["error"])
            self.assertEqual(2, unknown.returncode)
            self.assertIn("does not resolve", json.loads(unknown.stdout)["error"])

    def test_finding_demotion_after_snapshot_blocks_final_acceptance(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = initialize_repository(Path(temp))
            created = json.loads(self.run_helper(repository).stdout)
            worktree = Path(created["worktree"])
            session = repository / "output" / "state" / "remediation-session.json"
            (worktree / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
            snapshot = json.loads(
                self.command(
                    "snapshot",
                    str(session),
                    "--message",
                    "fix: close audit finding",
                    "--finding-ref",
                    "finding-1",
                ).stdout
            )
            findings = session.parent / "findings.jsonl"
            findings.write_text(
                json.dumps(
                    {
                        "schema_version": "finding.v1",
                        "run_id": "run-123",
                        "fingerprint": "finding-1",
                        "maturity": "Candidate",
                        "minimal_fix": "No longer approved.",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            accepted = self.command(
                "accept",
                str(session),
                "--reviewed-digest",
                snapshot["review"]["diff_digest"],
            )

            self.assertEqual(2, accepted.returncode)
            self.assertIn("Confirmed finding", json.loads(accepted.stdout)["error"])
            self.assertEqual(created["source_head"], git(repository, "rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()
