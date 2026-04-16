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
- `surface-auditor`
  Broad review of an explicitly owned service, route family, subsystem, or audit surface.
- `validator`
  Validates high-signal findings, attack paths, bypasses, and cross-shard chain steps.

Optional specialized roles:
- `shared-surface-auditor`
  Owns cross-cutting helpers and trust boundaries such as auth, storage, serialization, template/prompt wrappers, queues, and path-building helpers.
- `dependency-auditor`
  Focuses on dependency ecosystems and SCA normalization when the repo shape justifies it.

## Hard Rules

- only the `supervisor` may emit final findings, final severity, and final report text
- worker agents may suggest candidates, evidence, and validation results only
- worker agents may suggest hypotheses, but only the `supervisor` may keep the shared hypothesis ledger or emit a final `Working Hypotheses` appendix
- all worker-to-supervisor communication should follow `execution/worker-contract.md`
- workers must not write shared audit state directly; they hand off deltas and requests to the `supervisor`
- every worker must maintain a mergeable local state delta covering coverage counts, bounded function chains, and agent logs for its owned scope
- all worker output must be normalized through `core/findings.md` and `core/severity.md`
- all history matching and dedupe must pass through `core/fingerprints.md`
- in `quick`, `standard`, and `deep`, the `supervisor` must treat history as deferred post-scan comparison only; do not read prior report details before recon, current-code scanning, and worker kickoff are already underway
- in `quick`, `standard`, and `deep`, kickoff commentary must not say that workers will start after reading history "for background" or any equivalent pre-scan framing
- do not let parallel workers duplicate the same area without an explicit reason
- use disjoint ownership when possible: by service, subsystem, or audit surface
- do not discard a low- or medium-severity worker finding merely because it looks small in isolation when it may bridge a material attack chain
- do not let workers privately invent cross-shard conclusions; route them back through the `supervisor` as chain candidates or handoff requests
- the `supervisor` must merge worker coverage totals, function-chain deltas, and agent logs into shared audit state before final reporting

Use:
- `execution/sharding.md` to assign ownership
- `execution/worker-contract.md` to structure handoffs
- `execution/merge.md` to merge worker output

## Recommended Pairing

- `quick`
  Usually stay single-agent unless the repo is very large.
- `standard`
  Good candidate for beta multi-agent when breadth matters.
- `deep`
  Highest-value use case for beta multi-agent.
