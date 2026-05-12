# Business Logic Vulnerability Router

Use this file as the routing overview for stateful workflow abuse that does not fit cleanly into authn, authz, injection, or infrastructure alone.

Business-logic flaws are about broken invariants:
- who can do what
- in which order
- how many times
- with which value or resource impact

---

## Module Map

- `references/application/vulnerabilities/pricing-and-accounting.md`
  Money, credits, balances, discounts, exchange rates, and settlement math.
- `references/application/vulnerabilities/state-machine-abuse.md`
  Invalid transitions, skipped prerequisite states, and terminal-state abuse.
- `references/application/vulnerabilities/limits-and-quotas.md`
  Quotas, caps, counts, free-tier abuse, and aggregate limits.
- `references/application/vulnerabilities/workflow-replay.md`
  Reuse of one-time steps, claims, tokens, coupons, and idempotency gaps.
- `references/application/vulnerabilities/race-conditions.md`
  Concurrency-specific state corruption, replay amplification, and TOCTOU.

---

## How To Use This Router

Load this file when the repo handles:
- money, credits, rewards, or settlement
- explicit workflow states or approvals
- quotas, storage caps, or trial entitlements
- one-time links, claims, coupons, or finalize flows

Then route immediately to the focused modules above instead of keeping all logic review inside one monolith.

---

## Cross-Cutting Questions

- What invariant must stay true before and after this action?
- Which actor is allowed to trigger it?
- What resource, balance, or workflow state changes if it succeeds?
- Can a low-severity weakness in one step combine with authz, deserialization, file handling, or another business step to create higher impact?
- Is the control authoritative server-side, or only advisory in the client, preview, or signed state?

---

## Detection Methodology

### Actor x Action x Resource Matrix

For each sensitive flow, map:
- actor: user, admin, support, worker, webhook, scheduler
- action: create, update, approve, redeem, refund, finalize, export
- resource: order, balance, file, token, plan, tenant, claim

Look for combinations that were never meant to exist.

### Invariant Validation Checklist

- values stay within allowed bounds
- transitions follow the intended order
- one-time actions cannot be replayed
- quotas and counts are enforced on the real source of truth
- fixes that seem small in isolation are checked for compound-chain impact

---

## Deep Semantic Gate

In `deep` mode, create a `business_invariant` gate for each sensitive business flow involving money, credits, approvals, entitlements, quotas, lifecycle states, one-time actions, or resource ownership.

The gate is not `covered` until the audit records:
- the invariant in enforceable terms, including actor, action, resource, value bounds, allowed order, replay limits, and final state
- every entry path that can affect the invariant: public API, admin/support UI, mobile, webhook, worker, scheduler, import/export, retry, and compensating job
- source of truth for values and state, including server recomputation, signed state, cached previews, provider callbacks, ledger entries, quota counters, and database constraints
- dependency semantics for payment/provider retries, workflow libraries, queue delivery, cache consistency, ORM transactions, rate-limit stores, and signed-state verification when relevant
- negative evidence that client-controlled values, stale previews, alternate transitions, duplicate execution, partial failures, and compound chains cannot break the invariant
- proof obligations for provider behavior, runtime feature flags, deployment topology, or external workflow state that cannot be verified locally

Record design/implementation conflicts when:
- docs say a workflow is one-time, terminal, server-priced, quota-limited, or approval-gated but implementation allows alternate paths or weaker source-of-truth checks
- public, admin, webhook, and worker paths enforce different invariants for the same resource
- a preview, quote, signed value, or cached count is treated as authoritative during final settlement or mutation

If the invariant cannot be reconstructed across all state-changing paths, keep the gate `partial` and create coverage debt.

---

## Related References

- `references/application/vulnerabilities/authentication.md`
- `references/application/vulnerabilities/authorization.md`
- `references/application/vulnerabilities/mass-assignment.md`
- `references/application/vulnerabilities/race-conditions.md`
