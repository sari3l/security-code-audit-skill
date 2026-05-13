# Audit State Standard

Use this standard to keep every audit coherent without turning past state into a substitute for fresh review.

This module defines the machine-readable audit state stored under `.security-code-audit-state/`.

---

## Purpose

Audit state exists to:
- preserve the current scan's compact working context when repo size or scan length would otherwise cause compression drift
- preserve a lightweight advisory code fact snapshot so AI has a stable map of observed files, entrypoints, routes, candidate sources, candidate sinks, state transitions, artifact surfaces, and known limitations
- preserve flexible evidence observations so raw AI notes, tool output, blockers, negative evidence, and unknown-shaped signals survive before they are promoted, rejected, merged, or routed to coverage debt
- preserve complex smart-contract reasoning when accounting, oracle, signature, upgrade, or multi-contract trust analysis would otherwise exceed working context
- compare the current surface against prior snapshots so changed control surfaces are re-audited aggressively
- support `quick` incremental-first scope selection from reliable git or audit-surface diffs without turning stored state into proof of safety
- keep route, auth, dependency, sink, function-chain, and coverage inventories in a format that can be diffed across runs
- preserve key audit decisions and per-agent logs in a mergeable machine-readable form

Audit state does **not** exist to:
- prove unchanged code is safe
- prove that code or behavior missing from `code_fact_snapshot` is absent
- prove that prior history findings are fixed or no longer reachable
- reject an observation because it does not fit a known vulnerability class, source/sink family, or schema shape
- skip fresh recon
- replace full reports in `.security-code-audit-reports/`
- permanently store conclusions that should be revalidated

---

## State Reading Semantics

State reading is a runtime interpretation step, not a separate component, file, schema, service, or platform subsystem. Do not create a `state-reader` module just because diagrams name this operation.

When prior state exists, read and summarize it into three hint groups:

1. `freshness_and_invalidation`
   - whether the prior snapshot is comparable to current git/tree/fs state
   - which shared helpers, trust boundaries, dependencies, configs, contracts, or artifact surfaces were invalidated
   - whether `quick` may safely use incremental-first scope selection or must ask about expanding to full quick scope

2. `continuation_and_open_obligations`
   - unresolved proof obligations
   - partial or blocked deep gates
   - material working hypotheses or evidence observations that still need routing

3. `coverage_and_merge_ledgers`
   - counted coverage status
   - function-chain records
   - worker deltas and agent logs in beta `multi`
   - merge blockers, schema gaps, and coverage debt candidates

These hint groups may guide recon, audit context, and consolidation. They never replace current-code reading, current evidence, required coverage, or the historical-miss gate.

---

## Directory Layout

Use:

```text
.security-code-audit-state/
  latest.json
  index.json
  runs/
    {timestamp}-{snapshot_type}-{snapshot_id}.json
```

Optional future subdirectories:

```text
.security-code-audit-state/
  inventories/
  sca/
```

Keep the initial implementation small. Start with `latest.json`, `index.json`, and `runs/`.

Before first creating `.security-code-audit-state/`, load and apply `references/shared/audit-artifact-initialization.md` so ignore rules are aligned with `.security-code-audit-reports/`.

Do not create `.security-code-audit-state/` as an empty placeholder. If the directory exists, it should already contain machine-readable state files.

---

## Activation Rule

Load audit state for every run.

This is mandatory for:
- single-agent runs
- beta `multi` runs
- small repos
- large repos
- first-time audits
- regression retests

The old large / long-running / multi / state-worthy triggers now decide how much detail the snapshot should carry, not whether state exists at all.

Treat these smart-contract surfaces as requiring richer state detail even in small repos:
- accounting, precision, share-price, or invariant-sensitive logic
- permit, signature, or meta-transaction flows
- oracle, price, or MEV-sensitive assumptions
- proxy, upgrade, initializer, or deployment trust paths
- multi-contract calls, delegation, callbacks, or other cross-contract trust boundaries

The trigger is complexity, not line count. Small contract repos can still need state.

---

## Naming Rules

Use second-level timestamps:
- `YYYY-MM-DD-HHMMSS`
- always use the real current local time for the snapshot
- do not substitute example values such as `120000` or `000000` unless they are the true current time
- preferred acquisition source is the execution environment clock, for example:
  - `date '+%Y-%m-%d-%H%M%S %Z'`
- if both filename and metadata are written, they should come from the same captured timestamp

Use one of these snapshot types:
- `git`
- `tree`
- `fs`

Preferred per-run filenames:

- git repo:
  `{timestamp}-git-{short_commit}.json`
- non-git repo with stable project snapshot hash:
  `{timestamp}-tree-{short_tree_hash}.json`
- last-resort filesystem snapshot:
  `{timestamp}-fs-{short_fingerprint}.json`

Examples:
- `2026-03-23-154501-git-a1b2c3d.json`
- `2026-03-23-154501-tree-9f8e7d6.json`

`timestamp` is the ordering key.
`snapshot_type + snapshot_id` identifies the code snapshot.

---

## Snapshot Identity

Always record:
- `timestamp`
- `run_id`
- `skill_version`
- `mode`
- `execution`
- `audit_profile`
- `knowledge_domain`
- `snapshot_type`
- `snapshot_id`

Preferred identity sources:

1. git repo
   - `snapshot_type: git`
   - `snapshot_id: short commit hash`
   - also record `dirty: true|false`
   - when `dirty: true`, quick mode should still derive working-tree deltas separately instead of assuming the commit hash alone describes the live scope

2. non-git repo with stable audit-surface hash
   - `snapshot_type: tree`
   - `snapshot_id: short tree hash` derived from the stable aggregate hash of the audit-relevant file inventory

3. fallback only
   - `snapshot_type: fs`
   - `snapshot_id: short filesystem fingerprint`

The non-git hash should be derived from the audit-relevant surface, not from every file in the repo.

Include only:
- source files
- templates/views
- manifests and lock files
- config / IaC files
- prompt / artifact files that affect trust boundaries

Prefer a flat audit-relevant `file_inventory` plus one `aggregate_hash`.
Do not require a directory-level Merkle tree for the initial incremental contract.

---

## Required Files

### `latest.json`

Pointer to the most recent usable state snapshot.

Should include:
- `timestamp`
- `snapshot_type`
- `snapshot_id`
- `path`
- `skill_version`

### `index.json`

Small index of recent snapshots and migration notes.

Should include:
- `latest`
- `recent_runs`
- `prior_reports_detected`
- `notes`

### `runs/{...}.json`

Per-run compact context snapshot.

This is the most important file for scan-state precision retention.

---

## Run Context Shape

Keep each run file compact and structured.

Recommended top-level fields:
- `meta`
- `repo`
- `surfaces`
- `project_context`
- `code_fact_snapshot`
- `evidence_observations`
- `loaded_modules`
- `tool_invocations`
- `coverage_ledger`
- `deep_gate_ledger`
- `dependency_semantics_ledger`
- `design_implementation_conflicts`
- `proof_obligations`
- `semantic_assumptions`
- `trace_checkpoints`
- `function_chain_index`
- `hypothesis_ledger`
- `audit_log`
- `agent_logs`
- `invalidations`

### `meta`

Record:
- `timestamp`
- `run_id`
- `skill_version`
- `mode`
- `execution`
- `audit_profile`
- `knowledge_domain`

### `repo`

Record:
- `root`
- `snapshot_type`
- `snapshot_id`
- `dirty`
- `repo_id`
- `baseline_snapshot_type` when the current run compares against a prior state snapshot
- `baseline_snapshot_id` when the current run compares against a prior state snapshot

### `surfaces`

Record compact observed inventories such as:
- routes and handlers
- auth and authz control surfaces
- dependency managers and lockfile digests
- sink families
- artifact surfaces
- smart-contract trust/accounting/signature/oracle surfaces
- audit-relevant `file_inventory`
- stable `aggregate_hash`

Do not store large code excerpts here.

For `file_inventory`, prefer one compact entry per audit-relevant file with:
- `path`
- `surface_kind`
- `content_hash`

Keep `file_inventory` flat and compact. Do not store full blobs, large excerpts, or directory-tree proofs.

### `project_context`

Record compact project intent, architecture, business, deployment, and trust-boundary context derived during recon.

Apply `core/project-context.md` and `core/untrusted-repo-input.md` before using repo-authored prose or git history as context.

Prefer:
- `claimed_purpose`
- `architecture_summary`
- `business_flows`
- `trust_boundaries`
- `declared_roles`
- `deployment_assumptions`
- `git_change_themes`
- `security_relevant_invariants`
- `claim_verification`
- `context_conflicts`

For material claims, preserve verification state rather than flattening claims into facts.

Recommended claim verification fields:
- `claim`
- `source`
- `source_type`
- `expected_control`
- `verification_evidence`
- `result`
- `security_relevance`

Recommended claim verification results:
- `unverified`
- `validated`
- `contradicted`
- `partial`
- `stale`
- `not_applicable`

Do not store full README content, full commit logs, large doc excerpts, or raw issue exports here.

### `code_fact_snapshot`

Store a lightweight advisory code fact layer for the current run.

This is a repo-orientation snapshot, not a platform indexer, full static-analysis IR, or proof of absence.

Prefer:
- `file_inventory`
- `entrypoints`
- `routes`
- `security_relevant_functions`
- `source_candidates`
- `sink_candidates`
- `state_transition_candidates`
- `dependency_manifests`
- `artifact_surfaces`
- `parser_notes`
- `limitations`

For each fact, prefer compact references:
- `id`
- `kind`
- `location`
- `name`
- `evidence_ref`
- `confidence`
- `limitations`

Recommended confidence values:
- `observed`
- `inferred`
- `partial`
- `unknown`

Hard rules:
- missing entries do not prove absence
- dynamic routes, generated code, reflection, framework magic, plugin behavior, build-time artifacts, and repo-authored instruction flow must become `limitations` or coverage-debt candidates when material
- do not require IDE-grade symbol resolution, directory-level Merkle trees, or whole-program call graphs
- do not store full source excerpts or large generated inventories here
- if a discovered fact does not fit a known field, preserve it under `extensions` or as an `evidence_observations` item with a `custom:*` label

### `evidence_observations`

Store a flexible evidence envelope for high-signal observations before they become report outcomes.

Use this for:
- AI raw observations and analyst notes
- suspicious candidates not yet proven
- concrete negative evidence
- blockers and unresolved proof gaps
- compact external tool-output summaries
- historical replay signals
- unknown-shaped or schema-conflicting signals

Each observation should preserve enough raw context to be mergeable and auditable without becoming a second report.

Prefer:
- `id`
- `kind`
- `summary`
- `locations`
- `raw_evidence`
- `normalized_labels`
- `trace_links`
- `confidence`
- `provenance`
- `open_questions`
- `status`
- `routed_to`
- `extensions`

Recommended `kind` values:
- `hypothesis`
- `candidate`
- `confirmed_evidence`
- `negative_evidence`
- `blocker`
- `tool_output`
- `history_signal`
- `coverage_signal`
- `schema_gap`
- `unstructured_hypothesis`

Recommended `provenance` values:
- `ai`
- `tool`
- `history`
- `manual`
- `repo_context`

Recommended `status` values:
- `open`
- `routed`
- `merged`
- `rejected`
- `deprioritized`
- `superseded`

Recommended `routed_to` values:
- `confirmed_finding`
- `candidate_signal`
- `negative_evidence`
- `coverage_debt`
- `working_hypothesis`
- `integration_assumption`
- `operational_risk`
- `engineering_note`
- `skill_optimization_suggestion`
- `none`

Hard rules:
- this envelope is not a closed finding schema
- labels are open-ended; allow `custom:*`
- keep `extensions` open for unknown fields
- schema mismatches must survive as `schema_gap`, `unstructured_hypothesis`, or `custom:*` observations instead of being dropped
- observations do not count as confirmed findings until `core/findings.md` and `references/shared/reporting/evidence-standard.md` promote them
- raw scanner output should not be stored wholesale; store compact summaries, file references, or extracted evidence instead
- before final reporting, every high-signal open observation must be routed, rejected with negative evidence, or carried as coverage debt / working hypothesis / schema-gap suggestion

### `loaded_modules`

Record only the actually loaded modules and the reason they were loaded.

This helps restore context without reloading the whole tree.

### `tool_invocations`

Record compact external tool and repo-script resolution decisions.

Apply `references/shared/tooling/command-resolution.md` before invoking optional scanners or repo-defined audit commands whose name, subcommands, or flags may vary by environment.

Prefer:
- `surface`
- `ecosystem` or `domain`
- `candidate`
- `candidate_source`
- `resolution_source`
- `probe_commands`
- `tool_version`
- `help_result`
- `executed_command`
- `exit_code`
- `status`
- `limitations`

Recommended statuses:
- `executed`
- `unavailable`
- `unsupported`
- `blocked`
- `skipped_unsafe`
- `manual_fallback`

Do not store large raw scanner output here. Store normalized dependency, IaC, secret, or smart-contract findings in the report.

### `coverage_ledger`

For each major surface, track:
- `applicable_total`
- `pending`
- `in_progress`
- `reviewed`
- `partial`
- `invalidated`
- `blocked`
- `time_boxed`
- `function_entries_total`
- `function_chains_recorded`
- `debt_total`

These counts are the source of truth for report-side coverage statistics.

### `deep_gate_ledger`

Use this ledger for durable deep semantic review checkpoints. It is required in `deep` mode and should also be used in `quick`, `standard`, or beta `multi` whenever a high-risk surface depends on design assumptions, dependency semantics, parser behavior, deployment reality, state-machine invariants, or other reasoning that may be lost to context compression.

This ledger complements `coverage_ledger`; it does not replace it. Coverage says whether a surface was reviewed. A deep gate records why the review was semantically complete enough, partial, blocked, or invalidated.

For each gate, prefer:
- `id`
- `surface`
- `status`
- `owner`
- `scope`
- `trust_boundaries`
- `entry_points`
- `critical_dependencies`
- `design_claims`
- `implementation_evidence`
- `negative_evidence`
- `evidence_observation_refs`
- `dependency_semantics_refs`
- `conflict_refs`
- `proof_obligation_refs`
- `coverage_debt_refs`
- `last_checkpoint`

Recommended statuses:
- `not_started`
- `in_progress`
- `partial`
- `blocked`
- `invalidated`
- `covered`

Hard rules:
- a high-risk `deep` surface may not be marked covered only because its category or domain row is checked
- `covered` requires the relevant surface-specific gate requirements, evidence refs, and negative evidence
- `partial`, `blocked`, `invalidated`, or missing gate output for an in-scope high-risk surface must create coverage debt before final reporting
- gate progress should be persisted incrementally after meaningful review, not reconstructed only at report time
- do not store full source files, long prose, raw scanner output, or unbounded call graphs in this ledger

### `dependency_semantics_ledger`

Track dependency behavior when exploitability, remediation, or a design claim depends on more than a version number.

Examples:
- URL parser and HTTP client redirect behavior for SSRF
- ORM raw-query, identifier quoting, or query-builder behavior for SQL injection
- template engine escaping and sanitizer behavior for XSS
- serializer polymorphism and type materialization behavior for deserialization
- object-storage SDK presign, ACL, metadata, or content-type behavior for file flows
- smart-contract oracle adapter, token, proxy, math, or access-control library semantics

For each entry, prefer:
- `id`
- `dependency`
- `version_or_source`
- `surface`
- `assumed_behavior`
- `observed_or_documented_behavior`
- `evidence_refs`
- `risk_if_wrong`
- `related_gates`
- `verification_status`

Recommended verification statuses:
- `unverified`
- `validated`
- `contradicted`
- `partial`
- `not_applicable`

### `design_implementation_conflicts`

Record material contradictions between repo-authored design claims, API specs, deployment files, comments, dependency behavior, and implementation evidence.

For each conflict, prefer:
- `id`
- `claim`
- `claim_source`
- `implementation_evidence`
- `conflict_type`
- `affected_surfaces`
- `security_relevance`
- `resolution_status`
- `related_gates`
- `related_findings`
- `related_observations`

Recommended conflict types:
- `design_vs_code`
- `docs_vs_config`
- `dependency_semantics`
- `deployment_exposure`
- `sibling_path_drift`
- `version_drift`

Recommended resolution statuses:
- `open`
- `validated`
- `rejected`
- `accepted_assumption`
- `converted_to_finding`
- `converted_to_coverage_debt`
- `converted_to_observation`

### `proof_obligations`

Use this ledger for specific unanswered proof steps whose answer can change coverage, severity, or finding status.

For each obligation, prefer:
- `id`
- `question`
- `related_gate`
- `related_surface`
- `owner`
- `next_validation_step`
- `status`
- `evidence_for`
- `evidence_against`
- `blocker`
- `report_destination`
- `related_observations`

Recommended statuses:
- `open`
- `in_progress`
- `satisfied`
- `rejected`
- `blocked`
- `deferred`

Recommended report destinations:
- `finding`
- `candidate_signal`
- `coverage_debt`
- `working_hypothesis`
- `integration_assumption`
- `none`

### `semantic_assumptions`

Track assumptions that are material to exploitation, severity, or safe operation but are not themselves findings.

For each assumption, prefer:
- `id`
- `assumption`
- `owner`
- `scope`
- `evidence_refs`
- `confidence`
- `risk_if_false`
- `related_gates`
- `report_destination`

Use this ledger for compact operational, deployment, and economic assumptions that should survive context compression without being inflated into vulnerabilities.

### `trace_checkpoints`

Record bounded checkpoints rather than raw whole-repo call graphs.

For each active trace, prefer recording:
- `id`
- `surface`
- `source_or_entry`
- `join_checkpoints`
- `sink_or_transition`
- `status`
- `bounded_reason`
- `related_functions`
- `owner`

Recommended statuses:
- `in_progress`
- `bounded`
- `blocked`
- `invalidated`

### `function_chain_index`

For every security-relevant function or state-changing transition placed into scope, record a bounded call-chain entry.

For each entry, prefer recording:
- `id`
- `function`
- `surface`
- `why_in_scope`
- `entry_paths`
- `join_checkpoints`
- `sink_or_transition`
- `status`
- `truncation_or_blocker`
- `related_findings`
- `owner`

### `hypothesis_ledger`

Track current high-signal hypotheses such as:
- suspected attack chains
- suspected shared vulnerable helpers
- trust boundaries needing confirmation
- likely false-positive candidates needing stronger proof

For each hypothesis, prefer recording:
- `id`
- `type`
- `status`
- `related_surfaces`
- `why_it_matters`
- `evidence_for`
- `evidence_against`
- `next_validation_step`
- `owner` when execution is `multi`

Recommended statuses:
- `open`
- `validated`
- `rejected`
- `deprioritized`

Use `Candidate Signals` for localized suspected vulnerabilities.
Use the hypothesis ledger for broader attack-chain, trust-boundary, shared-root-cause, or proof-challenge models.

When `deep` mode or beta `multi` execution produces material unresolved hypotheses, map them into the report appendix using `references/shared/reporting/hypothesis-standard.md`.

### `audit_log`

Record compact run-level decisions such as:
- why a surface was prioritized
- why a path was bounded
- why a function chain was truncated
- why a blocker created coverage debt
- why a hypothesis was escalated or rejected

Prefer fields:
- `timestamp`
- `stage`
- `summary`
- `evidence_refs`
- `owner`

### `agent_logs`

Always include at least one agent log entry for the primary agent.

When execution is `multi`, include supervisor and worker log streams in one mergeable structure.

Prefer fields:
- `agent_id`
- `agent_role`
- `owned_scope`
- `events`

### `invalidations`

Track why a previously reviewed surface needs renewed attention:
- route or handler changed
- auth middleware changed
- shared helper changed
- config / IaC changed
- dependency / lockfile changed
- signer / oracle / proxy path changed

Prefer fields:
- `diff_basis`
- `baseline_snapshot`
- `changed_files`
- `changed_shared_surfaces`
- `shared_surface_hits`
- `expansion_recommended`
- `expansion_reason`
- `user_expansion_decision`

---

## Re-Audit Rules

State should influence priority, not replace review.

Hard rules:
- every scan still performs fresh recon
- unchanged surfaces are not automatically safe
- `quick` may narrow its initial scope from committed delta plus working-tree delta, or from non-git inventory diff, but that narrowing never proves the untouched remainder is safe
- shared auth, authz, helper, sink, or config changes invalidate dependent surfaces
- high-risk surfaces should still receive periodic deep review even without obvious diffs

Use state to answer:
- what changed
- what was already deeply reviewed
- what likely needs immediate re-audit

Do not use state to answer:
- what is definitely safe
- what can be skipped forever

---

## Update Guidance

For every run:
1. initialize a run context early in recon
2. update the surface profile, `file_inventory`, `aggregate_hash`, `code_fact_snapshot`, coverage ledger, deep gate ledger, dependency semantics ledger, proof obligations, trace checkpoints, and function-chain index as the scan progresses
3. append high-signal `evidence_observations` before promotion, rejection, merge, or coverage-debt routing
4. append key audit-log, invalidation, and agent-log entries at stage transitions and decision points
5. revisit the run context before stage `5/6` and final reporting

For large, long-running, or beta `multi` runs:
- keep owner fields filled
- preserve more checkpoint detail
- keep cross-shard function-chain joins explicit
- keep worker-local evidence observations mergeable and route them through the supervisor before final reporting

Execution rule:
- before first creating `.security-code-audit-state/`, apply `references/shared/audit-artifact-initialization.md`
- create the directory only at the moment the first state file is written
- write a minimal usable state during or immediately after recon
- if the run cannot persist `latest.json`, `index.json`, or a `runs/{...}.json` snapshot, do not leave an empty state directory behind

Performance rule:
- prefer git-native diff queries over rebuilding hashes when git metadata exists
- for non-git comparison, hash only audit-relevant files needed for `file_inventory`
- when incremental invalidation already fans out to most of the repo, ask before converting quick into an implicit full-scope run

---

## Reporting Boundary

`.security-code-audit-state/` is not the final report.

Use:
- `.security-code-audit-state/` for machine-readable working state
- `.security-code-audit-reports/` for human-readable findings and history

Coverage counts, function-chain counts, and agent-state evidence in the final report should reconcile back to `.security-code-audit-state/`.

Confirmed findings, candidate signals, coverage debt, working hypotheses, negative evidence, and schema-gap suggestions should reconcile back to `evidence_observations` when those observations were material to the decision.

If the two disagree, trust fresh code reading and current evidence over stored state.
