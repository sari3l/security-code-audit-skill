# Dangerous Capability Census

Use this control in every mode before category review or hypothesis pruning. Its purpose is to make high-risk execution and authority-bearing capabilities part of the coverage denominator even when exploitability is not yet proven.

## Hard Rule

Enumerate dangerous capabilities first, then trace sources, consumers, and security decisions. A capability hit is not automatically a confirmed vulnerability, but it must never disappear because the first payload fails or the exploit chain is incomplete.

Run a cheap whole-repository census in `quick`, `standard`, and `deep`, including files outside an incremental diff. At minimum include source files, shell scripts, shebang executables, Makefiles, Procfiles, systemd units, container entrypoints, CI steps, deployment scripts, and repo-tracked runtime configuration.

In `regression`, use the same families and ledger contract only for the baseline finding paths, affected helpers, configs, consumers, and trust boundaries. Record `scope: regression_targets`; do not imply a whole-repository census or expand the retest into a broad audit.

## Mandatory Sentinel Families

Always seed and reconcile these families when applicable:

- dynamic code evaluation: `eval`, `exec`, `compile`, string-to-code APIs, expression engines, dynamic module loading, and wrappers that invoke them
- shell command execution: `os.system`, `popen`, `subprocess`, `child_process`, `exec`, `spawn`, and shell command wrappers
- shell interpretation and code loading: `source`, `.`, shell `eval`, `sh -c`, `bash -c`, process substitution, command substitution in interpreted config, and wrappers that reintroduce a shell
- signing and authority material: hardcoded or predictable Flask/JWT/session/HMAC signing keys and insecure literal fallbacks
- signed-state consumers: session/token creation, parsing, reads, writes, membership tests, identity selection, and authorization decisions that trust signed state

Language and framework modules may add families. They may not remove these sentinels merely because a specialist module has not been loaded yet.

## Required State

Write `dangerous-capability-census.json` after the initial census with:

- `schema_version: "1.0"`
- `census_completed`
- `scope`
- `files_considered`
- `required_families`
- `family_totals`
- `discovered_total`
- `manual_search_evidence_refs` and optional tool-output refs

Write one `dangerous-capabilities.jsonl` record per occurrence. Use the common audit-state fields plus:

- `family`, `kind`, `location`, and a redacted `symbol_or_snippet`
- `source_reachability`: `reachable`, `not_reachable`, `unknown`, or `not_applicable`
- `disposition`: `unreviewed`, `confirmed_finding`, `high_risk_alert`, `candidate`, `negative_closed`, or `coverage_debt`
- `trace_refs`, `finding_refs`, `report_refs`, `negative_evidence`, and `coverage_debt_refs` as applicable

The closure equation is mandatory:

```text
discovered_total
  = confirmed_finding
  + high_risk_alert
  + candidate
  + negative_closed
  + coverage_debt
```

`unreviewed` must be zero before any complete claim. The ledger count and per-family totals must reconcile with the census summary.

## Disposition Rules

- `confirmed_finding`: current evidence proves a reachable failed control and concrete impact.
- `high_risk_alert`: an untrusted boundary reaches a dangerous capability, but direct injection or final impact is not yet proven. Keep it report-visible and prioritize removal.
- `candidate`: the capability or trust boundary is high signal but reachability or consumer semantics remain unresolved.
- `negative_closed`: current evidence proves stable isolation or benign semantics for this occurrence. Record specific negative evidence and the inspected consumers; a failed sample payload is insufficient.
- `coverage_debt`: required code, deployment facts, dependency semantics, or consumer paths could not be inspected. Keep it report-visible.

An API-, CLI-, queue-, CI-, or config-reachable dynamic evaluator cannot be silently removed or negative-closed merely because one serialization shape keeps a test string inert. Use `high_risk_alert` until the evaluator is removed or complete, stable isolation is demonstrated.

## Trace Obligations

For every occurrence:

1. identify every entry boundary and attacker-controlled component
2. decompose selector, code/expression text, parameters, namespace, working directory, environment, and downstream consumers instead of treating the call as one opaque value
3. trace backward from the capability to sources and forward through called handlers, signed-state consumers, authorization checks, or later interpreters
4. inspect allowlists separately for what they actually constrain; an allowlisted function name does not validate arguments or downstream handler behavior
5. record negative evidence, unknowns, and a removal-oriented minimal fix

When signing material is found, route by use. A Flask session signing key must trigger authentication review and consumer tracing, not remain only in a generic secret-leak finding.

## Reporting Gate

Confirmed vulnerabilities, high-risk alerts, candidates, and coverage debt need stable report references. `negative_closed` records may remain in state, but must contain concrete negative evidence. Do not merge capabilities with different exploit paths or minimal fixes merely because they share a file or secret-scanner hit.

Optional deterministic seeders may help enumerate literal patterns. Their silence never proves absence; perform manual language/framework-aware review and preserve unsupported shapes as evidence observations or coverage debt.
