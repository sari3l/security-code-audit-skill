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

## Related References

- `references/application/vulnerabilities/authentication.md`
- `references/application/vulnerabilities/authorization.md`
- `references/application/vulnerabilities/mass-assignment.md`
- `references/application/vulnerabilities/race-conditions.md`
