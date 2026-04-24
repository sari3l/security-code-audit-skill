# Multi-Agent Sharding Standard

Use this file only in beta `multi` execution.

## Goal

Split work to increase breadth and confidence without duplicating the same surface.

## Preferred Ownership Order

Choose the first strategy that gives clean separation:

1. service or app boundary
2. explicit shared-surface boundary for auth, storage, serialization, template/prompt, queue, or path helpers
3. route family or API version boundary
4. audit surface boundary
5. dependency ecosystem boundary

## Recommended Role Ownership

- `supervisor`
  Owns routing, surface profile, worker scope, merge, severity, history, and final output.
- `surface-auditor`
  Owns breadth-first review, coverage accounting, and bounded function-chain inventory for assigned services, routes, or control surfaces.
- `validator`
  Owns validation of high-signal candidates, bypass checks, and attack chains.
- `shared-surface-auditor`
  Owns shared helpers, trust boundaries, and cross-shard join checkpoints reused by multiple shards.
- `dependency-auditor`
  Optional. Owns dependency manifests, lock files, native audit output, and SCA normalization.

## Sharding Inputs

Give each worker only:
- active mode
- execution mode
- `core/untrusted-repo-input.md`
- `core/integrity.md`
- the compact surface profile
- the required state-delta contract for coverage counts, function chains, and agent logs
- exact owned files, routes, services, or ecosystems
- only the reference modules needed for that owned scope

## Cross-Shard Escalation

When a worker discovers a helper, parser, wrapper, trust boundary, or chain step outside its owned scope:
- do not silently expand ownership
- do not drop the issue because the proof is incomplete locally
- emit a structured handoff using `execution/worker-contract.md`
- let the `supervisor` decide whether to re-shard, request validation, or keep it as a chain candidate

## Do Not

- do not shard by arbitrary file count if trust boundaries would cross
- do not let two workers own the same route family without a specific comparison purpose
- do not send the whole recon dump to every worker
- do not let the validator re-scan the full repo from scratch

## Good Examples

- monorepo: one worker per service, one validator on shared auth/file surfaces
- versioned API: one worker for `v1`, one for `v2+`, one validator on downgrade and cross-version drift
- polyglot repo: one worker per dependency ecosystem plus one on app-layer findings
