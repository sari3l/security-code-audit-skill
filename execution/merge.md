# Multi-Agent Merge Standard

Use this file only in beta `multi` execution.

## Goal

Merge worker output into one consistent result set with low duplication and stable severity.
In audit state, merge also normalizes worker deltas into shared ledgers and clears or routes `merge-queue.jsonl` items.

## Required Normalization

Before a candidate becomes a finding, the supervisor must normalize:
- project-context claim verification, business invariants, git change themes, and context conflicts
- code fact deltas, including limitations and unknown dynamic or generated surfaces
- evidence observation deltas, including raw AI observations, tool output, blockers, negative evidence, schema gaps, and unknown-shaped signals
- tool invocation records, command-resolution blockers, skipped unsafe scripts, and manual fallbacks
- coverage totals and ownership
- deep gate status, dependency semantics, design/implementation conflicts, proof obligations, semantic assumptions, evidence refs, negative evidence, and coverage debt refs
- trace checkpoints and invalidations
- function-chain deltas and join checkpoints
- agent-log deltas that explain bounded paths, blockers, and routing decisions
- evidence quality
- finding fingerprint
- affected locations
- exploitability claim
- severity suggestion
- history status
- chain candidates and cross-shard handoff requests
- unresolved hypothesis status and ownership when workers are carrying attack-chain or trust-boundary theories
- audit state common fields: stable id, run id, scope, owner, freshness status, evidence refs, and sequence/lease provenance
- merge queue outcome: `merged`, `rejected`, or `routed`, with final-blocking items resolved before report generation

## Merge Order

1. exact same fingerprint
2. same vulnerability family plus same route or resource family
3. same dependency advisory normalized across native tooling and external SCA
4. same tool invocation or scanner result normalized across workers
5. same evidence observation or schema gap reported across workers
6. compound chain correlation when multiple small findings together create materially higher impact

## Conflict Rules

- code evidence beats summary prose
- verified code/config evidence beats repo-authored claims and commit-message claims
- current-run evidence beats prior state and promoted knowledge
- invalidated state records cannot support covered, fixed, complete, or confirmed decisions
- exploit proof may upgrade confidence, but not override missing evidence
- use the lower severity when evidence is split, unless the higher severity has direct proof
- if workers disagree on scope, keep separate findings until the fix path is clearly shared
- unresolved ambiguity becomes a note, not a main finding
- do not suppress a bridge finding just because it is low severity alone if it materially enables a validated or still-open chain candidate
- do not promote a compound chain into final severity without concrete evidence that the steps compose in the reviewed target
- do not mark a surface fully covered until merged function-chain counts and coverage totals agree
- do not mark the run complete until audit state quality gates pass or failures are represented as coverage debt / blocked scan
- do not mark a high-risk deep gate `covered` until its surface-specific requirements, evidence refs, negative evidence, dependency semantics, and open proof obligations have been reconciled
- do not treat a scanner as run unless command resolution and execution evidence are present, or a blocker/manual fallback is recorded
- do not drop a worker observation because it does not fit existing vulnerability labels; keep it as `schema_gap`, `unstructured_hypothesis`, or `custom:*` until the supervisor routes it

## Finalization Rules

- only the supervisor emits final finding titles, severity, and history status
- only the supervisor writes shared audit state ledgers and `quality-gates.json`
- only the supervisor emits final working-hypothesis entries
- only the supervisor may assign compound chain severity or collapse multiple worker findings into one shared root-cause finding
- only the supervisor may finalize the shared coverage summary, merged function-chain section, and merged agent-log-backed audit state
- only the supervisor may finalize shared `deep-gates.jsonl`, `dependency-semantics.jsonl`, `design-conflicts.jsonl`, `proof-obligations.jsonl`, and semantic assumptions
- only the supervisor may finalize shared advisory inventory/index records and `evidence-observations.jsonl`
- only the supervisor may promote runtime records into `knowledge/`, and only when evidence, scope, confidence, freshness, and invalidation rules are present
- every confirmed finding, attack chain, candidate signal, coverage debt item, and report-visible hypothesis must link back to current-run state record ids when material
- apply `core/fingerprints.md` before `references/shared/reporting/history-standard.md`
- apply `core/severity.md` before `references/shared/reporting/severity-guide.md`
- attach multiple locations to one finding only when fingerprint and remediation match

## Output Shape

For each merged finding, keep:
- fingerprint
- category
- title
- severity
- status
- owned evidence locations
- exploit notes
- related findings or chain refs when material
- related function-chain refs when material
- related evidence-observation refs when material
- related trace / function-chain / attack-chain refs when material
- freshness status for any prior-state or knowledge input used during validation
- minimal fix
- surviving working-hypothesis notes when a chain or shared-root-cause theory remains materially unresolved
