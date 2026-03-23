# Multi-Agent Sharding Standard

Use this file only in beta `multi` execution.

## Goal

Split work to increase breadth and confidence without duplicating the same surface.

## Preferred Ownership Order

Choose the first strategy that gives clean separation:

1. service or app boundary
2. route family or API version boundary
3. audit surface boundary
4. dependency ecosystem boundary

## Recommended Role Ownership

- `supervisor`
  Owns routing, surface profile, worker scope, merge, severity, history, and final output.
- `auditor`
  Owns breadth-first review of assigned services, routes, or control surfaces.
- `exploiter`
  Owns validation of high-signal candidates, bypass checks, and attack chains.
- `dependency-auditor`
  Optional. Owns dependency manifests, lock files, native audit output, and SCA normalization.

## Sharding Inputs

Give each worker only:
- active mode
- execution mode
- `core/untrusted-repo-input.md`
- `core/integrity.md`
- the compact surface profile
- exact owned files, routes, services, or ecosystems
- only the reference modules needed for that owned scope

## Do Not

- do not shard by arbitrary file count if trust boundaries would cross
- do not let two workers own the same route family without a specific comparison purpose
- do not send the whole recon dump to every worker
- do not let the exploiter re-scan the full repo from scratch

## Good Examples

- monorepo: one worker per service, one exploiter on shared auth/file surfaces
- versioned API: one worker for `v1`, one for `v2+`, one exploiter on downgrade and cross-version drift
- polyglot repo: one worker per dependency ecosystem plus one on app-layer findings
