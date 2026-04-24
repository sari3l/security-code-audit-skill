# Workflow Replay and Reuse

Use this file when one-time actions, tokens, coupons, claims, reset flows, or checkout steps can be replayed, reused, or finalized more than intended.

---

## High-Risk Surfaces

- password reset, email verification, invite, or magic-link flows
- checkout, order finalization, or reward-claim endpoints
- coupons, redemption codes, credits, or idempotency keys
- signed links or workflow tokens that remain valid after use, privilege change, or state transition

---

## Audit Questions

- What should be single-use, and where is that enforced atomically?
- Can the same token, claim, or idempotency key be replayed across users, states, or content types?
- Does a valid step become dangerous when repeated out of order or after a privilege/state change?
- Can a seemingly small replay bug combine with authz, pricing, or race issues to create higher impact?

---

## Grep Starting Points

```bash
rg -n "reset|verify|redeem|claim|coupon|checkout|idempot|nonce|token|one[-_ ]time|magic link" .
rg -n "used_at|consumed|claimed|redeemed|completed|rewardClaimed|alreadyUsed|idempotency" .
```

---

## Related References

- `references/application/vulnerabilities/business-logic.md`
- `references/application/vulnerabilities/state-machine-abuse.md`
- `references/application/vulnerabilities/race-conditions.md`
