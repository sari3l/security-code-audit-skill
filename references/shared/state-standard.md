# Audit State Standard

Use this standard to keep every audit coherent without turning past state into a substitute for fresh review.

This module defines the machine-readable audit state stored under `.security-code-audit-state/`.

---

## Purpose

Audit state exists to:
- preserve the current scan's compact working context when repo size or scan length would otherwise cause compression drift
- preserve complex smart-contract reasoning when accounting, oracle, signature, upgrade, or multi-contract trust analysis would otherwise exceed working context
- compare the current surface against prior snapshots so changed control surfaces are re-audited aggressively
- support `quick` incremental-first scope selection from reliable git or audit-surface diffs without turning stored state into proof of safety
- keep route, auth, dependency, sink, function-chain, and coverage inventories in a format that can be diffed across runs
- preserve key audit decisions and per-agent logs in a mergeable machine-readable form

Audit state does **not** exist to:
- prove unchanged code is safe
- skip fresh recon
- replace full reports in `.security-code-audit-reports/`
- permanently store conclusions that should be revalidated

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
- `loaded_modules`
- `coverage_ledger`
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

### `loaded_modules`

Record only the actually loaded modules and the reason they were loaded.

This helps restore context without reloading the whole tree.

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
2. update the surface profile, `file_inventory`, `aggregate_hash`, coverage ledger, trace checkpoints, and function-chain index as the scan progresses
3. append key audit-log, invalidation, and agent-log entries at stage transitions and decision points
4. revisit the run context before stage `5/6` and final reporting

For large, long-running, or beta `multi` runs:
- keep owner fields filled
- preserve more checkpoint detail
- keep cross-shard function-chain joins explicit

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

If the two disagree, trust fresh code reading and current evidence over stored state.
