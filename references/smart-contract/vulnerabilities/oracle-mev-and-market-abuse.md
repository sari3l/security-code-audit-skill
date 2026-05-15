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

## Deep Semantic Gate

In `deep` mode, create an `oracle_market_abuse` entry in audit state `deep-gates.jsonl` for every price-sensitive or liquidity-sensitive trust boundary.

The gate is not `covered` until the audit records:
- every trusted price source, adapter, fallback, reserve read, TWAP, off-chain signer, and keeper-fed value that can influence mint, borrow, redeem, liquidation, settlement, or reward math
- dependency semantics for each oracle or adapter, including decimals, answer type, stale-round behavior, round completeness, heartbeat expectations, revert behavior, and whether zero or negative answers can appear
- implementation evidence for freshness, deviation, upper/lower bounds, zero/negative handling, fallback ordering, pause/circuit-breaker behavior, and same-transaction manipulation resistance
- normalization and rounding evidence for converting oracle answers into protocol accounting units, including who benefits from truncation or rounding
- consumer mapping: every state-changing function that consumes the price and the invariant it is expected to preserve
- negative evidence showing that spot price, low-liquidity reserve state, stale data, dependency semantic mismatch, or same-transaction reserve shaping does not drive a profitable path
- proof obligations for any runtime-only liquidity, heartbeat, deployment, or off-chain signer assumption that cannot be verified from code and config

Record design/implementation conflicts when:
- documentation claims TWAP or independent oracle use but code reads spot reserves or manipulable balances
- a dependency's decimals, round, or failure semantics differ from the code's assumptions
- one consumer applies bounds, min-out, freshness, or circuit-breaker checks while a sibling consumer of the same price source does not
- fallback logic silently accepts stale, zero, negative, or lower-confidence data after the primary source fails

If any of these checks is incomplete for an in-scope price-sensitive path, keep the gate `partial` or `blocked` and create coverage debt instead of marking Oracle / Market Abuse covered.

---

## Reporting Guidance

Separate:
- raw code weakness
- economic assumptions needed for exploitation
- realistic profit path under expected market conditions

If the weakness is only profitable above a certain liquidity or slippage threshold, state that explicitly rather than flattening it into a yes/no claim.

---

## Remediation Notes

- Do not recommend generic "use TWAP" or "add slippage checks" if the protocol still trusts an attacker-shapeable source for the critical decision.
- Minimal fixes should change the trust boundary that creates profit, such as switching to an independent oracle, enforcing freshness/deviation guards, or preventing same-transaction user-controlled reserve shaping from driving settlement.
- Parameter tuning alone is hardening unless it actually makes the exploit path impossible under the protocol's stated threat model.
- Preserve intended market behavior where possible. A fix that freezes liquidations, minting, or redemption under normal volatility may be necessary, but it is not a minimal fix unless the report says why narrower controls are insufficient.
- State the exact impossible post-fix condition, such as: "an attacker can no longer profit by moving the trusted price source within the same transaction or stale-oracle window."
