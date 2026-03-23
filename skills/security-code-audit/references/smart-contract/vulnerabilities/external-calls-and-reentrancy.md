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
