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
- which sibling helpers enforce the same invariant, threshold, or minimum-output rule across open, manage, exit, queue, and claim paths

---

## High-Risk Patterns

- linear mint or redeem math where proportional accounting is expected
- share inflation caused by rounding toward the attacker
- stale cached totals reused across multiple user actions
- fee-on-transfer or rebasing tokens treated like standard ERC20
- precision truncation around low-liquidity or low-share states
- preview helpers disagreeing with actual state-changing functions
- exchange-rate logic that can be nudged through dust, donation, or temporary price moves
- one helper applies a dust, slippage, or rounding threshold while a sibling helper on the same invariant still uses a raw zero check
- partial remediation that fixes the open path but leaves manage, exit, queue, or claim helpers on stale threshold or rounding logic
- rebasing-token delta accounting that ignores token-specific 1-2 wei rounding behavior and turns edge-case drift into operational DoS

---

## Deep Checks

- zero-state or near-zero-state bootstrapping
- first depositor / first minter advantage
- withdraw asymmetry after partial redemption
- donation or griefing effects on future users
- liquidation or reward distribution using stale totals
- mixed-decimal assets, wrappers, LP tokens, and synthetic assets
- compare equivalent invariants across open, add, withdraw, adjust, exit, queue, and claim helpers instead of reviewing each helper in isolation
- verify dust thresholds, min-out checks, and rounding guards stay symmetric wherever the same balance source or collateral relationship is reused

---

## Audit Questions

- What invariant should always hold between assets and shares?
- Who benefits from each rounding direction?
- Does the system behave safely with 6, 8, 18, and mismatched decimals?
- What happens if tokens burn, skim fees, rebase, or return less than requested?
- Can a tiny capital injection create a large accounting edge for later actions?
- If a prior bug was "fixed," was the same invariant actually updated in every sibling helper and state transition?
- Can dust, donation, rebasing drift, or rounding residuals block management or exit even though the open path now looks safe?
- Do balance-before / balance-after reads tolerate token-specific rounding quirks without converting them into false insolvency or hard reverts?

---

## Deep Semantic Gate

In `deep` mode, create an `accounting_precision` entry in `deep_gate_ledger` for every asset/share/debt/collateral/reward invariant in scope.

The gate is not `covered` until the audit records:
- the source of truth for every accounting unit: assets, shares, collateral, debt, rewards, fees, indexes, cached totals, virtual offsets, and external balances
- a rounding matrix for mint, burn, deposit, withdraw, redeem, borrow, repay, liquidate, claim, preview, quote, and conversion helpers that identifies direction, precision unit, and beneficiary
- dependency semantics for token behavior, math libraries, oracle adapters, vault standards, wrappers, LP tokens, rebasing behavior, fee-on-transfer behavior, and decimals
- zero-state and near-zero-state behavior, including first depositor/minter, dust, donation, bootstrap, and low-liquidity cases
- preview/action consistency: every preview, quote, simulation, or off-chain estimate that is expected to match a state-changing path
- sibling-helper consistency across open, manage, adjust, queue, exit, claim, liquidate, emergency, and admin paths sharing the same invariant
- negative evidence showing that rounding residuals, donations, rebasing drift, stale totals, cached values, or mixed decimals cannot become attacker profit or operational DoS
- proof obligations for any economic or token-behavior assumption that cannot be verified locally

Record design/implementation conflicts when:
- documentation or comments describe proportional accounting but the implementation uses linear or stale totals
- a fix or guard exists on one helper while a sibling path still uses a raw zero check, different precision, or weaker threshold
- dependency or token semantics contradict assumptions about transfer amount, balance delta, decimals, or rounding
- preview/quote helpers disagree with the state-changing function in a way that affects user safety or liquidation/settlement behavior

If the invariant cannot be reconstructed end to end, keep the gate `partial` or `blocked` and create coverage debt. Do not replace missing invariant reconstruction with a generic "rounding reviewed" note.

---

## Typical Reporting Language

- share inflation
- rounding bias
- precision loss
- accounting drift
- non-standard token incompatibility
- donation or bootstrap manipulation
- partial-fix drift
- helper inconsistency
- dust-threshold mismatch

---

## Remediation Notes

- Do not recommend "just increase precision" when the real bug is wrong proportional math, stale totals, or the wrong accounting source of truth.
- Minimal fixes should preserve the intended economic model while making the exploit path impossible, for example by correcting rounding direction, zero-state bootstrap rules, or asset/share conversion formulas.
- If the protocol claims support for rebasing, fee-on-transfer, or mixed-decimal assets, avoid suggesting a silent de-support as the default fix unless the product surface truly allows that narrowing.
- If no local patch can restore the invariant safely, say that the accounting model needs redesign instead of forcing a one-line fix.
- State the exact impossible post-fix condition, such as: "a user can no longer mint disproportionate shares through dust, donation, or first-depositor skew."
