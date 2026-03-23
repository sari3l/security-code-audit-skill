# Multi-Agent Merge Standard

Use this file only in beta `multi` execution.

## Goal

Merge worker output into one consistent result set with low duplication and stable severity.

## Required Normalization

Before a candidate becomes a finding, the supervisor must normalize:
- evidence quality
- finding fingerprint
- affected locations
- exploitability claim
- severity suggestion
- history status
- unresolved hypothesis status and ownership when workers are carrying attack-chain or trust-boundary theories

## Merge Order

1. exact same fingerprint
2. same vulnerability family plus same route or resource family
3. same dependency advisory normalized across native tooling and external SCA

## Conflict Rules

- code evidence beats summary prose
- exploit proof may upgrade confidence, but not override missing evidence
- use the lower severity when evidence is split, unless the higher severity has direct proof
- if workers disagree on scope, keep separate findings until the fix path is clearly shared
- unresolved ambiguity becomes a note, not a main finding

## Finalization Rules

- only the supervisor emits final finding titles, severity, and history status
- only the supervisor emits final working-hypothesis entries
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
- minimal fix
- surviving working-hypothesis notes when a chain or shared-root-cause theory remains materially unresolved
