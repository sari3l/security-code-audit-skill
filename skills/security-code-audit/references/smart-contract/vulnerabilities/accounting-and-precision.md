# Accounting And Precision

Use this file for share math, exchange rates, decimals, rebasing or fee-on-transfer behavior, and any invariant where small rounding errors can become attacker profit.

---

## Core Review Goal

Reconstruct the protocol's accounting model before deciding whether a bug exists.

Track:
- source of truth for assets, shares, debt, collateral, reward index, and fees
- when values are rounded up or down
- what assumptions are made about token decimals and transfer behavior
- how mint, burn, deposit, withdraw, redeem, borrow, liquidate, and claim interact over time

---

## High-Risk Patterns

- linear mint or redeem math where proportional accounting is expected
- share inflation caused by rounding toward the attacker
- stale cached totals reused across multiple user actions
- fee-on-transfer or rebasing tokens treated like standard ERC20
- precision truncation around low-liquidity or low-share states
- preview helpers disagreeing with actual state-changing functions
- exchange-rate logic that can be nudged through dust, donation, or temporary price moves

---

## Deep Checks

- zero-state or near-zero-state bootstrapping
- first depositor / first minter advantage
- withdraw asymmetry after partial redemption
- donation or griefing effects on future users
- liquidation or reward distribution using stale totals
- mixed-decimal assets, wrappers, LP tokens, and synthetic assets

---

## Audit Questions

- What invariant should always hold between assets and shares?
- Who benefits from each rounding direction?
- Does the system behave safely with 6, 8, 18, and mismatched decimals?
- What happens if tokens burn, skim fees, rebase, or return less than requested?
- Can a tiny capital injection create a large accounting edge for later actions?

---

## Typical Reporting Language

- share inflation
- rounding bias
- precision loss
- accounting drift
- non-standard token incompatibility
- donation or bootstrap manipulation

---

## Remediation Notes

- Do not recommend "just increase precision" when the real bug is wrong proportional math, stale totals, or the wrong accounting source of truth.
- Minimal fixes should preserve the intended economic model while making the exploit path impossible, for example by correcting rounding direction, zero-state bootstrap rules, or asset/share conversion formulas.
- If the protocol claims support for rebasing, fee-on-transfer, or mixed-decimal assets, avoid suggesting a silent de-support as the default fix unless the product surface truly allows that narrowing.
- If no local patch can restore the invariant safely, say that the accounting model needs redesign instead of forcing a one-line fix.
- State the exact impossible post-fix condition, such as: "a user can no longer mint disproportionate shares through dust, donation, or first-depositor skew."
