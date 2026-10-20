from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read_doc(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class SkillContractTests(unittest.TestCase):
    def test_skill_frontmatter_uses_only_supported_fields(self):
        skill = read_doc("SKILL.md")
        frontmatter = skill.split("---", 2)[1]
        fields = re.findall(r"^([A-Za-z][A-Za-z0-9_-]*):", frontmatter, re.MULTILINE)

        self.assertEqual(["name", "description"], fields)

    def test_dangerous_capability_census_is_a_mandatory_cross_mode_gate(self):
        paths = [
            "SKILL.md",
            "core/loading.md",
            "core/coverage.md",
            "modes/quick.md",
            "modes/standard.md",
            "modes/deep.md",
            "modes/regression.md",
            "references/shared/state-standard.md",
        ]
        combined = "\n".join(read_doc(path) for path in paths)

        self.assertIn("core/dangerous-capability-census.md", combined)
        self.assertIn("dangerous-capability-census.json", combined)
        self.assertIn("dangerous-capabilities.jsonl", combined)
        self.assertIn("high-risk alert", combined)
        self.assertIn("unreviewed", combined)
        self.assertIn("dangerous-capability-seed.jsonl", combined)
        self.assertIn("shell_command_execution", combined)
        self.assertIn("--target-root", combined)

    def test_requirement_context_is_mandatory_after_recon_across_modes(self):
        paths = [
            "SKILL.md",
            "core/loading.md",
            "core/requirements-context.md",
            "modes/quick.md",
            "modes/standard.md",
            "modes/deep.md",
            "modes/regression.md",
            "references/shared/state-standard.md",
        ]
        documents = {path: read_doc(path) for path in paths}
        combined = "\n".join(documents.values())

        self.assertIn("core/requirements-context.md", documents["SKILL.md"])
        self.assertIn("core/requirements-context.md", documents["core/loading.md"])
        for mode in ("quick", "standard", "deep", "regression"):
            self.assertIn("requirements-context.json", documents[f"modes/{mode}.md"])
        self.assertIn("requirements-context.json", documents["references/shared/state-standard.md"])
        self.assertIn("never execute target-repository connectors", combined)
        self.assertIn("never reduces audit scope", combined)
        requirement_controls = documents["core/requirements-context.md"]
        for document in (requirement_controls,):
            self.assertIn("auth.configured: true", document)
            self.assertIn("missing_auth", document)
            self.assertIn("do not call", document.lower())
            self.assertIn("change_references", document)
            self.assertIn("MR1412", document)
            self.assertIn("Never ask the user", document)
        self.assertIn("automatically invoke", documents["SKILL.md"])

    def test_requirement_context_release_version_is_consistent(self):
        for path in ("SKILL.md", "README.md", "VERSIONING.md"):
            self.assertIn("4.1.0", read_doc(path), path)

    def test_auto_fix_requires_isolation_and_separate_final_acceptance(self):
        documents = {
            path: read_doc(path)
            for path in (
                "SKILL.md",
                "README.md",
                "core/loading.md",
                "core/remediation-worktree.md",
                "references/shared/state-standard.md",
            )
        }
        combined = "\n".join(documents.values())

        self.assertIn("--auto-fix", documents["SKILL.md"])
        self.assertIn("--auto-fix", documents["README.md"])
        self.assertIn("remediation-session.json", combined)
        self.assertIn("remediation_worktree.py create", combined)
        self.assertIn("remediation_worktree.py snapshot", combined)
        self.assertIn("remediation_worktree.py integrate", combined)
        self.assertIn("git merge\n   --ff-only", documents["core/remediation-worktree.md"])
        self.assertIn("explicit final acceptance", combined)
        self.assertIn("does not authorize commit, merge, push", documents["core/remediation-worktree.md"])
        self.assertIn("source worktree", documents["core/remediation-worktree.md"])
        self.assertIn("do not mistake `--auto-fix`", read_doc("modes/index.md"))
        self.assertIn("orthogonal remediation flag `--auto-fix`", read_doc("execution/index.md"))

    def test_default_mode_is_deep_and_core_skill_stays_compact(self):
        skill = read_doc("SKILL.md")
        modes = read_doc("modes/index.md")
        readme = read_doc("README-CN.md")

        self.assertLessEqual(len(skill.splitlines()), 500)
        self.assertIn("none / `deep`", skill)
        self.assertIn("If no argument is provided, use `deep`.", modes)
        self.assertIn("这等价于 `deep single`", readme)
        self.assertNotIn("Equivalent to `standard single`", skill)

    def test_source_bound_gates_have_no_manual_bypass(self):
        skill = read_doc("SKILL.md")
        reporting = read_doc("references/shared/reporting/index.md")

        self.assertIn("dangerous_capability_seed.py <target-root> --state-dir <state-dir>", skill)
        self.assertIn("audit_state_check.py <state-dir> --target-root <target-root>", skill)
        self.assertIn("report_gate_check.py <report> --run-dir <state-dir> --target-root <target-root>", skill)
        self.assertNotIn("equivalent manual gate", reporting)

    def test_eval_shell_source_and_flask_signing_chains_have_specialist_rules(self):
        eval_rules = read_doc("references/application/vulnerabilities/dynamic-code-evaluation.md")
        shell_rules = read_doc("references/application/vulnerabilities/shell-code-loading.md")
        flask_rules = read_doc("references/application/frameworks/python_flask.md")
        hardcoding_rules = read_doc("references/application/vulnerabilities/sensitive-hardcoding.md")

        self.assertIn("dict.__repr__", eval_rules)
        self.assertIn("report-visible `high_risk_alert`", eval_rules)
        self.assertIn("source", shell_rules)
        self.assertIn("command substitution executes", shell_rules)
        self.assertIn("Mandatory consumer trace", flask_rules)
        self.assertIn("offline", flask_rules)
        self.assertIn("independent C2 finding", hardcoding_rules)

    def test_readme_uses_agent_neutral_usage_heading(self):
        readme = read_doc("README-CN.md")

        self.assertNotIn("在 Codex 里使用", readme)
        self.assertIn("在Agent里使用", readme)

    def test_report_history_uses_run_directory_output_contract(self):
        paths = [
            "README.md",
            "SKILL.md",
            "modes/quick.md",
            "modes/standard.md",
            "modes/deep.md",
            "modes/regression.md",
            "references/shared/audit-artifact-initialization.md",
            "references/shared/reporting/history-standard.md",
            "references/shared/reporting/regression-standard.md",
            "references/shared/reporting/index.md",
        ]
        combined = "\n".join(read_doc(path) for path in paths)

        self.assertNotIn(".security-code-audit-reports", combined)
        self.assertIn("output/security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}.md", combined)
        self.assertNotIn("output/{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}.md", combined)
        self.assertIn("running directory", combined)

    def test_scan_generated_artifacts_use_prefixed_output_contract(self):
        paths = [
            "SKILL.md",
            "references/shared/audit-artifact-initialization.md",
            "references/shared/state-standard.md",
            "references/shared/reporting/index.md",
            "references/shared/reporting/finding-detail-standard.md",
        ]
        combined = "\n".join(read_doc(path) for path in paths)

        self.assertIn("output/security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}-findings.jsonl", combined)
        self.assertIn("output/security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}-state/", combined)
        self.assertNotIn("output/findings.jsonl", combined)
        self.assertNotIn(".security-code-audit-state", read_doc("references/shared/audit-artifact-initialization.md"))

    def test_legacy_split_state_directory_is_detected_but_not_written(self):
        paths = [
            "SKILL.md",
            "modes/regression.md",
            "references/shared/state-standard.md",
            "references/shared/reporting/regression-standard.md",
        ]
        combined = "\n".join(read_doc(path) for path in paths)

        self.assertIn(".security-code-audit-state/", combined)
        self.assertIn("legacy_split_state_detected", combined)
        self.assertIn("must not write", combined)
        self.assertIn("regression", combined)


    def test_exploration_is_open_but_durable_and_evidence_closes(self):
        paths = [
            "SKILL.md",
            "core/exploration-and-evidence.md",
            "core/coverage.md",
            "references/shared/state-standard.md",
            "modes/quick.md",
            "modes/standard.md",
            "modes/deep.md",
            "modes/regression.md",
        ]
        combined = "\n".join(read_doc(path) for path in paths)

        self.assertIn("exploration-ledger.jsonl", combined)
        self.assertIn("not a closed boundary", combined)
        self.assertIn("disconfirmation", combined)
        self.assertIn("entry/caller", combined)
        self.assertIn("external semantics", combined)

    def test_contract_coverage_expands_authorization_and_integration_surfaces(self):
        coverage = read_doc("references/smart-contract/vulnerabilities/coverage.md")
        module = read_doc(
            "references/smart-contract/vulnerabilities/authorization-and-integration.md"
        )
        skill = read_doc("SKILL.md")

        for needle in (
            "Authorization And Asset Flow",
            "Cross-Contract Integration And Settlement",
            "State Keying, Limits And Replay",
        ):
            self.assertIn(needle, coverage)
            self.assertIn(needle, skill)
        self.assertIn("Capability-to-Asset", module)
        self.assertIn("gross or net", module)
        self.assertIn("spender", module)
        self.assertIn("actual balance deltas", module)

    def test_contract_context_ordering_and_lifecycle_rules_are_explicit(self):
        module = read_doc("references/smart-contract/vulnerabilities/authorization-and-integration.md")
        calls = read_doc("references/smart-contract/vulnerabilities/external-calls-and-reentrancy.md")
        coverage = read_doc("references/smart-contract/vulnerabilities/coverage.md")
        state = read_doc("references/shared/state-standard.md")

        for needle in ("delegatecall", "execution context", "CPI", "is_supported", "stale"):
            self.assertIn(needle, module)
        self.assertIn("pre-call state snapshot", calls)
        self.assertIn("post-call state write", calls)
        self.assertIn("Execution Context And Capability Lifecycle", coverage)
        self.assertIn("trace_refs", state)
        self.assertIn("state gate fails", state)
        self.assertIn("approveRestrictively", module)
        self.assertIn("caller/role", read_doc("references/shared/reporting/finding-detail-standard.md"))

    def test_execution_safety_and_independent_verification_are_routed(self):
        paths = [
            "SKILL.md",
            "core/loading.md",
            "core/execution-safety.md",
            "execution/index.md",
            "execution/single-agent.md",
            "execution/multi-agent.md",
            "execution/verification.md",
            "core/coverage.md",
            "core/findings.md",
            "references/shared/state-standard.md",
        ]
        combined = "\n".join(read_doc(path) for path in paths)

        self.assertIn("execution-safety.md", combined)
        self.assertIn("no external network", combined)
        self.assertIn("coverage_id", combined)
        self.assertIn("coverage critic", combined)
        self.assertIn("fresh verifier", combined)
        self.assertIn("verification-ledger.jsonl", combined)


if __name__ == "__main__":
    unittest.main()
