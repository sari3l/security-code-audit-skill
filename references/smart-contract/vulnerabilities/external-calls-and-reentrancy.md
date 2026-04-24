# External Calls And Reentrancy

Use this file for execution ordering, callback surfaces, delegation, and interactions with attacker-controlled contracts or tokens.

---

## What To Trace

- every `call`, `delegatecall`, low-level token transfer, and hook-capable interaction
- functions that call out before finalizing balances, shares, debt, or permissions
- callback-capable standards such as ERC777, ERC721, ERC1155, flash-loan hooks, and custom receiver interfaces
- paths where one function can reenter a related function instead of itself

---

## Commonly Missed

- CEI looks correct locally but another shared state path remains callable during callback
- `safeTransfer` or `transferFrom` is treated as side-effect free
- reentrancy guard applied to one entry point but not the paired settle/claim/withdraw path
- same `nonReentrant` guard suggested on a synchronous flash-loan or hook callback even though the outer entrypoint already holds the lock
- arbitrary target execution hidden behind adapters, plugins, vault hooks, or strategy contracts
- `delegatecall` used for extensibility without strict target control

---

## Audit Questions

- Does any external interaction happen before all critical state is committed?
- Can attacker-controlled token behavior reopen the flow?
- Can a callback alter allowance, debt, collateral, or reward state before settlement finishes?
- Can a strategy, adapter, or plugin execute arbitrary code in protocol context?
- Can flash liquidity produce a temporary invariant violation long enough to profit?

---

## Success Signals For Findings

- repeated settlement from one initiating action
- double-withdraw, double-claim, or under-collateralized borrow
- stale state consumed after callback mutation
- protocol context executing attacker-chosen logic

---

## Remediation Notes

- Before recommending `nonReentrant`, trace whether the vulnerable callback is invoked synchronously from an outer function that already uses the same guard.
- If the callback is part of the intended happy path, reusing the same guard can self-revert the protocol instead of safely fixing the bug.
- Prefer one of these minimal-fix patterns when they preserve behavior:
  - remove ETH/token payout from the callback and let the user pull funds later
  - move payout until after the callback-sensitive settlement window closes
  - add a dedicated callback-only guard or phase flag that blocks nested callback entry without blocking the initial flash-loan hook
- State the concrete impossible condition after the fix, such as: "user-controlled code can no longer run before flash-loan settlement completes."
