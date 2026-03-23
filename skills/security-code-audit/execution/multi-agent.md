# Multi-Agent Execution (Beta)

Beta execution mode for higher-assurance or larger audits.

## Beta Status

Always describe this mode as beta when it is selected.

If the host does not support sub-agents or delegation:
- explicitly state that beta multi-agent execution is unavailable
- fall back to `single`
- continue the audit instead of failing the whole run

## Use When

- the user explicitly requested `multi` or `--agents=multi`
- the repo is large, multi-service, or a monorepo
- `standard` or `deep` mode needs more breadth or independent verification

## Required Roles

- `supervisor`
  Primary agent. Owns scope, routing, dedupe, severity normalization, history reconciliation, and final report output.
- `auditor`
  Broad surface review. Enumerates candidates and repeated patterns.
- `exploiter`
  Validates high-signal findings, attack paths, bypasses, and chains.

Optional future role:
- `dependency-auditor`
  Focuses on dependency ecosystems and SCA normalization when the repo shape justifies it.

## Hard Rules

- only the `supervisor` may emit final findings, final severity, and final report text
- worker agents may suggest candidates, evidence, and validation results only
- worker agents may suggest hypotheses, but only the `supervisor` may keep the shared hypothesis ledger or emit a final `Working Hypotheses` appendix
- all worker output must be normalized through `core/findings.md` and `core/severity.md`
- all history matching and dedupe must pass through `core/fingerprints.md`
- do not let parallel workers duplicate the same area without an explicit reason
- use disjoint ownership when possible: by service, subsystem, or audit surface

Use:
- `execution/sharding.md` to assign ownership
- `execution/merge.md` to merge worker output

## Recommended Pairing

- `quick`
  Usually stay single-agent unless the repo is very large.
- `standard`
  Good candidate for beta multi-agent when breadth matters.
- `deep`
  Highest-value use case for beta multi-agent.
