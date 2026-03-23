# Audit State Standard

Use this standard to keep large, long-running, or high-complexity audits coherent without turning past state into a substitute for fresh review.

This module defines the machine-readable audit state stored under `.security-code-audit-state/`.

---

## Purpose

Audit state exists to:
- preserve the current scan's compact working context when repo size or scan length would otherwise cause compression drift
- preserve complex smart-contract reasoning when accounting, oracle, signature, upgrade, or multi-contract trust analysis would otherwise exceed working context
- compare the current surface against prior snapshots so changed control surfaces are re-audited aggressively
- keep route, auth, dependency, sink, and coverage inventories in a format that can be diffed across runs

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

---

## Activation Triggers

Load audit state when any of these are true:
- the repo is large
- the scan is expected to be long-running
- execution mode is `multi`
- `.security-code-audit-state/` already exists
- recon detects state-worthy smart-contract surfaces

Treat these smart-contract surfaces as state-worthy even in small repos:
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

2. non-git repo with stable audit-surface hash
   - `snapshot_type: tree`
   - `snapshot_id: short tree hash`

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
- `hypothesis_ledger`
- `invalidations`

### `meta`

Record:
- `timestamp`
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

### `surfaces`

Record compact observed inventories such as:
- routes and handlers
- auth and authz control surfaces
- dependency managers and lockfile digests
- sink families
- artifact surfaces
- smart-contract trust/accounting/signature/oracle surfaces

Do not store large code excerpts here.

### `loaded_modules`

Record only the actually loaded modules and the reason they were loaded.

This helps restore context without reloading the whole tree.

### `coverage_ledger`

For each major surface, track:
- `pending`
- `in_progress`
- `reviewed`
- `invalidated`
- `blocked`

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

### `invalidations`

Track why a previously reviewed surface needs renewed attention:
- route or handler changed
- auth middleware changed
- shared helper changed
- config / IaC changed
- dependency / lockfile changed
- signer / oracle / proxy path changed

---

## Re-Audit Rules

State should influence priority, not replace review.

Hard rules:
- every scan still performs fresh recon
- unchanged surfaces are not automatically safe
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

## Large-Repo Guidance

Load this standard when:
- the repo is large
- the scan is long-running
- execution mode is `multi`
- the repo already has `.security-code-audit-state/`
- you need to preserve scan precision across many stages

In these cases:
1. initialize a run context early in recon
2. update the surface profile and coverage ledger as the scan progresses
3. revisit the run context before stage `5/6` and final reporting

---

## Reporting Boundary

`.security-code-audit-state/` is not the final report.

Use:
- `.security-code-audit-state/` for machine-readable working state
- `.security-code-audit-reports/` for human-readable findings and history

If the two disagree, trust fresh code reading and current evidence over stored state.
