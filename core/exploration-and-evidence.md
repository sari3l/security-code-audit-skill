# Exploration And Evidence Closure

Use this control to preserve LLM exploration without allowing an unbounded or
unverifiable audit. The required census, domain coverage, state ledgers, and
quality gates are a floor. They are not a closed checklist and they must not
prevent the auditor from following a new trust boundary, caller, data shape,
state key, dependency, or economic invariant discovered during review.

## Exploration Contract

After recon, the auditor may open any branch that is relevant to security,
including sibling functions, inherited or overridden implementations, callers,
interfaces, mocks, deployment scripts, frontend or relayer transaction builders,
external integration contracts, and generated or reflected code. Lazy-loading
routes the minimum useful references; it does not restrict source exploration.

For each material branch, append an `exploration-ledger.jsonl` record with:

- `id`, `run_id`, `owner`, `trigger`, and `question`
- `scope` and `branch_type` (`fanout`, `integration`, `disconfirmation`,
  `invariant`, `history_reopen`, or `schema_gap`)
- `actions` and `evidence_refs`
- `result`, `negative_evidence`, and `next_action`
- `status`: `open`, `routed`, `closed`, or `blocked`

The ledger records why a branch was opened or stopped. It is not a permission
system and it does not replace the required coverage ledger.

## Mandatory Expansion Triggers

Open a local fan-out branch when any of these appears:

- a privileged caller can select a token, spender, recipient, route, strategy,
  adapter, or amount
- an amount, fee, limit, cooldown, nonce, or replay key is scoped by one
  dimension but the security claim depends on several dimensions
- an interface, mock, test, comment, or external contract implies a different
  gross/net, fee, decimal, return-value, callback, or settlement meaning
- a finding or candidate names one helper while sibling helpers share its
  invariant, state key, modifier, or sink
- a contract crosses a proxy, registry, factory, solver, relayer, oracle,
  keeper, Safe, frontend, deployment, or CI boundary
- a negative conclusion relies on one payload, one test, an allowlist, a
  serializer, or a caller assumption rather than stable reachability evidence

Expansion must cover materially equivalent occurrences before the original
observation can be closed. If the boundary cannot be inspected, preserve the
branch as a proof obligation or coverage debt.

## Reopening Rule

Finding one vulnerable helper creates a fan-out task; it does not close the
family. Re-open every sibling helper that shares its modifier, state key, token,
allowance, cooldown, callback, adapter, registry value, or downstream sink, then
re-check the immediate upstream caller and downstream settlement consumer. The
fan-out may close as negative evidence only after the same invariant and the
same attacker-controlled dimensions were compared at each sibling.

## Two-Pass Reasoning

Every material hypothesis receives both passes:

1. **Construction** — build the shortest reachable path from an entry boundary
   to the failed control and concrete asset, authority, accounting, or liveness
   impact.
2. **Disconfirmation** — search for the strongest competing explanation:
   alternate caller checks, state updates, sibling paths, external semantics,
   deployment constraints, and post-condition or balance-delta checks.

Do not stop after a plausible exploit, and do not close after a failed sample
payload. A hypothesis may be confirmed, candidate, negative-closed with stable
evidence, or carried as debt; it must never disappear because it does not fit a
known vulnerability label.

## Evidence Closure Contract

For each confirmed finding, high-risk alert, candidate, or material negative
closure, record an evidence chain in `trace-ledger.jsonl` and reference the
observations used. The minimum chain is:

```text
entry/caller
  -> decode/normalization and attacker-controlled parameters
  -> authentication / role / capability check
  -> state key and state transition
  -> external dependency or callback semantics
  -> asset / authority / data / liveness sink
  -> violated invariant and impact
```

The trace record must carry a stable `entry_point`, `source`,
`sink_or_transition`, `status`, and non-empty `evidence_refs`. For contract
flows, put caller/role, attacker-controlled parameters, authorization result,
state key, execution or external semantics, asset/result delta, and violated
invariant in explicit checkpoints or a structured `chain_dimensions` object;
location-only traces do not close the evidence obligation.

Contract audits must make token, recipient, spender, route, amount, fee,
deadline, nonce, and relevant account or mapping keys explicit. For settlement
flows, distinguish caller-supplied amount, gross amount, fee, net amount, and
actual balance delta. If an external solver, token, oracle, relayer, proxy, or
adapter defines the missing semantics, record the exact integration assumption
and keep it as a proof obligation or coverage debt until verified.

Every observation must be consumed by one of the trace, finding, attack-chain,
negative-evidence, hypothesis, or coverage-debt records. Dangling observations,
unreferenced negative claims, and findings supported only by a location or a
keyword fail evidence closure.

## Completion Rule

The audit may claim complete only when the mandatory coverage gates pass and
every material exploration branch is routed. Open exploration branches,
unresolved integration semantics, and unclosed disconfirmation passes are
report-visible debt or hypotheses; they are never silently treated as clean.
