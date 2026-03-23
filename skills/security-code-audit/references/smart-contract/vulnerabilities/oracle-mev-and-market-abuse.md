# Oracle, MEV, And Market Abuse

Use this file when prices, reserves, liquidity, liquidation thresholds, or time-sensitive state can be manipulated for profit.

---

## Review Focus

- what price source the protocol trusts
- how fresh that data must be
- whether spot state, pool reserves, or manipulable balances drive value decisions
- whether attacker-controlled sequencing or flash liquidity can create one-transaction profit

---

## High-Risk Patterns

- spot-price oracle trust for mint, borrow, redeem, or liquidation
- stale oracle values accepted without freshness or heartbeat checks
- low-liquidity pools used as authoritative pricing
- liquidation math that overreacts to temporary market moves
- MEV-sensitive flows with no slippage, delay, or price-band controls
- user actions priced against reserves the user can mutate in the same transaction

---

## Audit Questions

- Can an attacker move price or reserve state just long enough to profit?
- Does the protocol trust the same pool it allows users to manipulate?
- Are TWAP, heartbeat, deviation, or circuit-breaker assumptions actually enforced?
- Can liquidation, mint, or redeem occur against stale or attacker-shaped market data?
- Is economic exploitability blocked only by liquidity depth, or by real code-level controls?

---

## Reporting Guidance

Separate:
- raw code weakness
- economic assumptions needed for exploitation
- realistic profit path under expected market conditions

If the weakness is only profitable above a certain liquidity or slippage threshold, state that explicitly rather than flattening it into a yes/no claim.
