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
