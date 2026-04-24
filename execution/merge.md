# Multi-Agent Merge Standard

Use this file only in beta `multi` execution.

## Goal

Merge worker output into one consistent result set with low duplication and stable severity.

## Required Normalization

Before a candidate becomes a finding, the supervisor must normalize:
- coverage totals and ownership
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

## Merge Order

1. exact same fingerprint
2. same vulnerability family plus same route or resource family
3. same dependency advisory normalized across native tooling and external SCA
4. compound chain correlation when multiple small findings together create materially higher impact

## Conflict Rules

- code evidence beats summary prose
- exploit proof may upgrade confidence, but not override missing evidence
- use the lower severity when evidence is split, unless the higher severity has direct proof
- if workers disagree on scope, keep separate findings until the fix path is clearly shared
- unresolved ambiguity becomes a note, not a main finding
- do not suppress a bridge finding just because it is low severity alone if it materially enables a validated or still-open chain candidate
- do not promote a compound chain into final severity without concrete evidence that the steps compose in the reviewed target
- do not mark a surface fully covered until merged function-chain counts and coverage totals agree

## Finalization Rules

- only the supervisor emits final finding titles, severity, and history status
- only the supervisor emits final working-hypothesis entries
- only the supervisor may assign compound chain severity or collapse multiple worker findings into one shared root-cause finding
- only the supervisor may finalize the shared coverage summary, merged function-chain section, and merged agent-log-backed audit state
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
- minimal fix
- surviving working-hypothesis notes when a chain or shared-root-cause theory remains materially unresolved
