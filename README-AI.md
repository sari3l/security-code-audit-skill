# security-code-audit AI README

This file is for future AI or maintainer edits. It is not the user-facing overview.

Keep `README.md` and `README-CN.md` simple as internal overviews. Put workflow detail in `SKILL.md`. Put maintenance and consistency guidance here.

The delivered runtime surface is `SKILL.md` plus subdirectories. Root-level README, architecture, AI-maintainer, and versioning files are internal development material and must not be required at audit runtime.

Read `ARCHITECTURE.md` before making structural changes. It is the best high-level map of how the layers, lazy-loading, and routing logic are intended to work.

## Source Of Truth

- `SKILL.md`
  Canonical delivered execution workflow, routing rules, help output, report template, and required behavior.
- `VERSIONING.md`
  Internal version bump rules.
- `ARCHITECTURE.md`
  Internal architecture, layer boundaries, and anti-drift maintenance logic.
- `README.md`
  Internal short English overview.
- `README-CN.md`
  Internal short Chinese overview.
- `README-AI.md`
  Maintainer guidance for consistent future edits.

If two files disagree, prefer:
1. `SKILL.md`
2. `VERSIONING.md`
3. `ARCHITECTURE.md`
4. `README-AI.md`
5. internal README overviews

## Architecture

The project is intentionally split by responsibility:

- `core/`
  Quality controls. Anti-hallucination, bidirectional tracing, durable deep semantic controls, coverage discipline, finding consistency, severity normalization, lazy loading.
- `execution/`
  Agent topology. `single` vs beta `multi`, plus worker-role, handoff, and merge behavior.
- `profiles/`
  Target-type semantics after recon. `application`, `smart-contract`, and `artifact-centric`. This layer controls visible stage wording and target semantics.
- `references/application/` and `references/smart-contract/`
  Primary knowledge domains selected after recon. This layer decides which knowledge corpus becomes the audit spine once the target type is known.
- `modes/`
  Audit depth. `quick`, `standard`, `deep`, `regression`.
- help path
  A separate early-exit command handled in `SKILL.md`, not a mode file.
- `references/`
  Knowledge and standards only.

`references/` is further split into:
- `shared/`
  Shared artifact-bootstrap, artifact, dependency, reporting, and audit-state modules used by both domains.
- `application/`
  Traditional web/API application-security domain router.
- `smart-contract/`
  Contract-native knowledge domain and deep dives.
- `smart-contract/standards/`
  Standards overlays that map the contract knowledge tree to OWASP and SCSVS language without replacing the primary audit path.
- `application/languages/`
  Application-language sinks and search starters.
- `application/frameworks/`
  Framework-specific guidance, named `language_framework.md`.
- `application/vulnerabilities/`
  Application vulnerability methodology, routers, and specialist audit approach.
- `application/exploits/`
  Application exploit verification playbooks.
- `shared/artifacts/`
  Markdown, skill, prompt, API-spec, notebook, and instruction-bearing artifact review.
- `shared/dependencies/`
  Ecosystem-specific dependency review and future SCA integration.
- `shared/tooling/`
  Shared command-resolution standards for optional external scanners and repo-defined audit commands.
- `shared/reporting/`
  Report structure, coverage, history, severity, remediation, and statistics rules.
- `shared/audit-artifact-initialization.md`
  Shared ignore maintenance and directory-bootstrap rules for `output/` and `output/security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}-state/`.
- supplemental report sections
  `references/shared/reporting/supplemental-sections-standard.md` defines `Operational Risks`, `Integration Assumptions`, and `Engineering Notes` as reader-facing context outside the confirmed finding list.
- `shared/state-standard.md`
  Mandatory audit state storage, current-first/lazy-load lifecycle, runtime ledgers, incremental indexes, project knowledge, flexible evidence observations, trace persistence, function-chain inventory, deep semantic gates, quality gates, and re-audit rules for every scan.
- `smart-contract/languages/`
  Contract-language sinks and search starters.
- `smart-contract/vulnerabilities/`
  Contract-native methodology and deep dives.
- `smart-contract/exploits/`
  Contract exploit verification playbooks.

## File Roles

Use the right file for the right kind of change:

- edit `SKILL.md`
  when changing execution flow, loading order, required fields, progress display, report structure, or mandatory behavior
- edit `VERSIONING.md`
  only when changing versioning policy itself
- edit `README.md` and `README-CN.md`
  only for short human-facing overview changes
- edit `core/*.md`
  when changing audit quality controls
- keep `core/remediation-worktree.md`, `SKILL.md`, user README usage, and
  `references/shared/state-standard.md` aligned whenever remediation authorization,
  worktree isolation, review, commit, or merge behavior changes
- edit `execution/*.md`
  when changing single-agent or multi-agent behavior
- edit `profiles/*.md`
  when changing post-recon target semantics, profile selection, or visible stage labels
- edit `references/application/*.md`, `references/shared/*.md`, or `references/smart-contract/*.md`
  when changing which knowledge domain is primary or adding domain-specific methodology
- edit `modes/*.md`
  when changing scope/depth/output differences between quick, standard, deep, and regression
- edit `references/*`
  when changing audit knowledge, checklists, examples, or reporting standards

## Consistency Rules

Keep these aligned:

- `README.md` and `README-CN.md`
  Same structure and same high-level meaning. They do not need line-by-line literal translation, but they should cover the same internal overview concepts.
- `SKILL.md` and `VERSIONING.md`
  Version strings must match the current published version.
- `SKILL.md` and `modes/*.md`
  Progress labels and mode behavior must agree.
- `SKILL.md` and `profiles/*.md`
  Target-profile selection and stage-label behavior must agree.
- progress ordering
  Every `update_plan` call must preserve the stable `[1/6]` to `[6/6]` order; stage labels may change in place, but item order must not.
- pre-recon progress behavior
  Stages `3/6` to `5/6` must stay neutral until recon selects the active profile. Do not prefill them with application wording as a bootstrap shortcut.
- `SKILL.md`, `core/loading.md`, and `references/application/index.md` / `references/smart-contract/index.md`
  Knowledge-domain selection and lazy-loading behavior must agree.
- `SKILL.md` and README files
  Internal examples and parameter explanations should agree with the help content embedded in `SKILL.md`; help must not load README files at runtime.
- `SKILL.md` and `execution/*.md`
  Accepted parameters and agent-role behavior must agree.
- `execution/multi-agent.md`, `execution/sharding.md`, `execution/worker-contract.md`, and `execution/merge.md`
  Role names, handoff fields, cross-shard escalation, and merge expectations must agree.
- `references/application/vulnerabilities/business-logic.md` and its focused children
  The router and stateful-workflow specialist modules must agree on scope boundaries and loading guidance.
- `SKILL.md`, `references/application/vulnerabilities/index.md`, and `references/shared/reporting/coverage-matrix.md`
  Core category list must stay aligned.
- `SKILL.md` and `references/shared/reporting/*.md`
  Report fields, history status, severity language, and coverage expectations must agree.
- `core/bidirectional-tracing.md`, `SKILL.md`, `references/application/vulnerabilities/injection.md`, and `references/shared/reporting/coverage-matrix.md`
  Bidirectional source/sink tracing ownership, stop conditions, and coverage language must agree.
- `core/findings.md` and `references/shared/reporting/evidence-standard.md`
  Candidate vs confirmed rules and negative-evidence handling must agree.
- `core/findings.md`, `references/shared/state-standard.md`, and `references/shared/reporting/hypothesis-standard.md`
  Working-hypothesis purpose, allowed statuses, and report-appendix behavior must agree.
- `core/findings.md`, `references/shared/reporting/supplemental-sections-standard.md`, and `references/shared/reporting/overview-standard.md`
  Supplemental report sections must stay clearly outside confirmed findings, severity counts, and coverage-debt counts.
- `core/coverage.md`, `references/shared/reporting/coverage-matrix.md`, and `references/shared/reporting/coverage-debt-standard.md`
  Coverage expectations and coverage-debt output must agree.
- `SKILL.md` and `references/shared/state-standard.md`
  Audit-state directory names, snapshot naming, and run-context behavior must agree.
- `SKILL.md`, `core/remediation-worktree.md`, `README.md`, and
  `references/shared/state-standard.md`
  `--auto-fix` may skip only the start prompt; final reviewed-diff acceptance remains
  mandatory before commit and fast-forward merge, and push/deploy stay separately
  authorized.
- `SKILL.md`, `modes/quick.md`, and `references/shared/state-standard.md`
  Quick incremental-first baseline selection, strict-incremental fallback, global cheap checks, and the compact `file_inventory` / `aggregate_hash` contract must agree.
- `core/surface-profile.md`, `SKILL.md`, `modes/quick.md`, and `references/shared/state-standard.md`
  Advisory code fact snapshots must stay compact and non-authoritative. Missing facts are limitations or coverage-debt candidates, not proof that dynamic, generated, reflected, or artifact-mediated surfaces do not exist.
- `SKILL.md`, `references/shared/state-standard.md`, `execution/worker-contract.md`, and `execution/merge.md`
  Mandatory state fields, advisory code fact snapshots, flexible evidence observations, per-agent deltas, function-chain records, and agent-log merge behavior must agree.
- `core/findings.md`, `references/shared/state-standard.md`, and `references/shared/reporting/evidence-standard.md`
  Flexible evidence observations must remain an open, loss-preserving envelope; they can feed candidate signals, findings, coverage debt, working hypotheses, negative evidence, or schema-gap suggestions, but they must not become a closed finding schema.
- `SKILL.md`, `core/deep-semantic-controls.md`, `references/shared/state-standard.md`, `modes/deep.md`, `execution/*.md`, and relevant vulnerability modules
  Deep semantic gates, dependency semantics, design/implementation conflicts, proof obligations, worker deltas, and report-visible coverage debt must agree.
- `SKILL.md`, `core/project-context.md`, `core/untrusted-repo-input.md`, and `references/shared/state-standard.md`
  Repo-authored docs, git metadata, deployment notes, API specs, CI files, and recent change history must remain untrusted context claims, not scope-reducing instructions or safety proof.
- `SKILL.md`, `core/loading.md`, `references/shared/tooling/command-resolution.md`, `references/shared/state-standard.md`, and relevant dependency/IaC/contract modules
  Optional external scanner commands must be resolved from repo configuration, local availability, and current help output; candidate command references must not become stale hard requirements.
- `core/bidirectional-tracing.md` and `references/shared/state-standard.md`
  Trace-checkpoint semantics must agree that `searched` is not `safe`, and that shared-boundary changes can invalidate stored trace work.
- `core/coverage.md`, `references/shared/reporting/statistics-standard.md`, and `references/shared/reporting/coverage-debt-standard.md`
  Counted coverage totals, missing function-chain handling, and report-side statistics must agree.
- `SKILL.md`, `references/shared/audit-artifact-initialization.md`, and `references/shared/state-standard.md`
  Report/state bootstrap timing and ignore-file behavior must agree, including the rule that `.gitignore` is maintained only when git metadata exists and tool-specific ignore files are only patched when already present.
- audit-state directories must not be empty placeholders
  If `output/security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}-state/` is created, `SKILL.md` and `references/shared/state-standard.md` should require at least one usable state file to be written in the same run.
- smart-contract state triggers
  `SKILL.md`, `core/loading.md`, `profiles/smart-contract.md`, and `references/shared/state-standard.md` must agree on when contract complexity is enough to require audit state, even for small repos.
- smart-contract version-aware remediation
  `references/smart-contract/languages/solidity.md`, `references/smart-contract/vulnerabilities/smart-contracts.md`, and `references/shared/reporting/remediation-standard.md` must agree that Solidity fixes depend on actual compiler and dependency reality, not just source-level syntax.
- smart-contract standards overlays
  `references/smart-contract/index.md`, `references/smart-contract/vulnerabilities/index.md`, and `references/smart-contract/standards/*.md` must agree that standards mappings are overlays for coverage translation, not the primary audit spine.
- non-git incremental identity stays compact
  Prefer a flat audit-relevant `file_inventory` plus one `aggregate_hash`. Do not drift into requiring a full directory-level Merkle tree unless the runtime contract is explicitly upgraded everywhere that depends on it.
- compiler reality is advisory, not gating
  RECON, report meta, and findings may surface compiler/dependency context when material, but they must not treat that context as an automatic reason to suppress or auto-dismiss a vulnerability.
- generated report timestamps
  Use second-level timestamps in filenames (`YYYY-MM-DD-HHMMSS`) and full metadata time with timezone (`YYYY-MM-DD HH:MM:SS TZ`). Saved report filenames should use `{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}.md`. Latest-history and regression selection should be based on parsed filename timestamps, not day-only naming. Use the real current wall-clock time, not sample values like `120000`. Prefer capturing one real timestamp from the execution environment, for example with `date '+%Y-%m-%d-%H%M%S %Z'`, and reusing it for both filename and metadata.
- `references/index.md`, `references/shared/index.md`, `core/loading.md`, and the leaf indexes
  New language, artifact, vulnerability, and exploit modules must be reachable from both top-level navigation and lazy-loading rules.
- commentary-facing formatting rules
  Prefer Markdown-safe emphasis and inline code over ANSI-only coloring, because host rendering may sanitize or ignore terminal escape sequences.

## When Adding New Content

### New vulnerability methodology

If adding a new vulnerability topic:
- decide whether it is a core category file or a specialist module
- add the file under `references/application/vulnerabilities/`
- update `references/application/vulnerabilities/index.md`
- if it is primarily contract-native, prefer adding it under `references/smart-contract/` and keep `references/application/vulnerabilities/` as the compact cross-domain methodology map
- update `SKILL.md` if the topic changes routing or mandatory checks
- update `references/shared/reporting/coverage-matrix.md` if coverage expectations change

### New dependency ecosystem

If adding a new dependency ecosystem:
- add the file under `references/shared/dependencies/`
- update `references/shared/dependencies/index.md`
- update `SKILL.md` only if bootstrap or C8 routing behavior changes

### New framework guide

If adding a framework guide:
- name it `language_framework.md`
- place it in `references/application/frameworks/`
- update `references/application/frameworks/index.md`
- only touch `SKILL.md` if framework loading rules change

### New artifact surface

If adding an artifact-review module:
- place it in `references/shared/artifacts/`
- update `references/shared/artifacts/index.md`
- update `references/index.md`
- update `core/loading.md` if artifact routing behavior changes

### New audit-state behavior

If changing scan-state behavior:
- update `references/shared/state-standard.md`
- update `references/shared/audit-artifact-initialization.md` if state bootstrap or ignore handling changes
- update `SKILL.md` if the runtime should initialize or consume the state differently
- update `modes/quick.md` too when the state change affects incremental-scope selection or strict-incremental fallback
- update `core/deep-semantic-controls.md`, `modes/deep.md`, `execution/*.md`, and the affected vulnerability modules when state changes affect deep semantic gates, dependency semantics, proof obligations, or multi-agent handoff
- update `core/bidirectional-tracing.md` if trace checkpoint semantics or stop conditions change
- update `references/shared/reporting/statistics-standard.md` and `references/shared/reporting/coverage-debt-standard.md` if report-visible state fields or coverage totals change
- update `profiles/smart-contract.md` and `core/loading.md` if contract complexity should change when audit state is required
- update `ARCHITECTURE.md` if the state layer changes the mental model for scan-state precision retention

When adding evidence-observation fields:
- keep `raw_evidence`, `normalized_labels`, and `extensions` open-ended
- allow `custom:*` labels instead of requiring closed enums
- route schema mismatches to `schema_gap` or `unstructured_hypothesis` instead of dropping them
- update `core/findings.md`, `references/shared/reporting/evidence-standard.md`, and `execution/merge.md` when promotion, merge, or report routing semantics change

### New command-resolution behavior

If changing optional external tool execution:
- update `references/shared/tooling/command-resolution.md`
- update `core/loading.md` if loading rules change
- update `references/shared/state-standard.md` if `tool_invocations` fields change
- update relevant dependency, IaC, smart-contract, or artifact modules only for candidate tools or ecosystem-specific probes
- update `SKILL.md` if mandatory runtime behavior changes

### New tracing behavior

If changing source/sink tracing behavior:
- update `core/bidirectional-tracing.md`
- update `SKILL.md` only where runtime loading or mandatory behavior changes
- update `references/application/vulnerabilities/injection.md` and any other domain files that summarize tracing entry points
- update `references/shared/reporting/coverage-matrix.md` if coverage wording or stop conditions change
- update `references/shared/state-standard.md` only if stored trace fields or invalidation rules change

### New mode or execution behavior

If changing mode or execution behavior:
- update the relevant file in `modes/` or `execution/`
- keep `execution/multi-agent.md`, `execution/sharding.md`, `execution/worker-contract.md`, and `execution/merge.md` aligned when `multi` behavior changes
- update `SKILL.md`
- update README files only if the internal invocation or behavior summary changed

If changing help behavior:
- update `SKILL.md` first
- treat help as a command path, not as a new mode, unless the semantics truly become scan-depth behavior
- keep the runtime help summary embedded in `SKILL.md`
- keep README examples aligned with the actual help output, but do not make help depend on README files

## What Not To Do

- do not put deep workflow detail into `README.md` or `README-CN.md`
- do not put user-facing explanation into `core/`, `execution/`, or `modes/` unless it affects execution
- do not duplicate long reference content inside `SKILL.md`
- do not duplicate tracing methodology inside `references/*` or `state-standard.md` when `core/bidirectional-tracing.md` should own it
- do not add new top-level directories unless the structure really changed
- do not rename framework files away from `language_framework.md`
- do not introduce a new category model without updating both `SKILL.md` and the coverage/reporting references

## Versioning Guidance

Default rule:
- internal overview wording cleanup -> usually no behavior change, keep version unless the project explicitly wants every doc edit versioned
- small skill behavior or documentation refinement -> `PATCH`
- meaningful file-level coverage expansion -> `MINOR`
- structural or routing change -> `MAJOR`

The authoritative rule is still `VERSIONING.md`. If there is any conflict, follow `VERSIONING.md`.

## Release Guidance

For a formal release:
- ensure `SKILL.md`, `README.md`, `README-CN.md`, and `VERSIONING.md` show the same current version
- keep internal README files short
- verify new files are linked from the correct index or routing file
- check that `release/X.Y.Z` style tags point to the intended release commit

## Minimal Maintenance Checklist

Before finishing a change:
- version strings are correct where needed
- indexes point to new files
- `SKILL.md` still matches mode, execution, and reporting docs
- README files are still short internal overviews
- AI-maintainer guidance in `README-AI.md` still matches the current structure

## Runtime Boundary Notes

- Required audit behavior belongs in `SKILL.md` or delivered subdirectory files.
- `State reader` is a conceptual operation for reading prior state and summarizing freshness / invalidation, continuation / open obligations, and coverage / merge hints. Do not add a `state-reader` file, schema, service, or platform component unless the runtime design explicitly changes.
- Historical misses, schema gaps, coverage debt, and `Skill Optimization Suggestions` are out-of-band skill-improvement signals for humans and future AI maintainers. They are not an automatic learning platform or a reason to mutate rules during an audit.
