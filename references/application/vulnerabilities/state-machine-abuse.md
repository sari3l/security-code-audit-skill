# State Machine Abuse

Use this file when workflows depend on explicit states, prerequisite transitions, one-time terminal states, or privileged state changes.

---

## High-Risk Surfaces

- order, payment, approval, moderation, onboarding, or claim flows with explicit states
- status fields writable through weak DTOs or internal endpoints
- admin or support transitions that bypass the normal prerequisite checks
- terminal or one-way states that can still be changed or replayed

---

## Audit Questions

- What are the valid transitions, and where are they enforced?
- Can an attacker skip prerequisite states or revisit a terminal state?
- Are transition checks centralized, or duplicated across handlers and jobs?
- Does a shared helper or background job bypass the stricter public flow?

---

## Deep Semantic Gate

In `deep` mode, create a `state_machine_integrity` gate for each workflow whose security depends on explicit states, prerequisite transitions, terminal states, approvals, or privileged state changes.

The gate is not `covered` until the audit records:
- valid state graph, prerequisite checks, terminal states, rollback or cancellation rules, and privileged override paths
- every transition entry path: public handler, admin/support action, worker, scheduler, webhook, import/export, retry, and compensating job
- dependency semantics for workflow engines, ORM transactions, queue delivery, optimistic/pessimistic locking, and enum/state validation
- negative evidence that body-bound status fields, mass assignment, alternate routes, replay, out-of-order callbacks, and background jobs cannot skip or repeat protected transitions
- proof obligations for runtime feature flags, external callback ordering, or deployment-specific workers that cannot be verified locally

If the transition graph cannot be reconciled across all mutation paths, keep the gate `partial` and create coverage debt.

---

## Grep Starting Points

```bash
rg -n "status|state|transition|approve|publish|ship|deliver|refund|cancel|complete|finalize" .
rg -n "enum|STATE_|VALID_TRANSITIONS|canTransition|workflow|stateMachine|step" .
```

---

## Related References

- `references/application/vulnerabilities/business-logic.md`
- `references/application/vulnerabilities/workflow-replay.md`
- `references/application/vulnerabilities/race-conditions.md`
