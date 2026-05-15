# External Calls And Reentrancy

Use this file for execution ordering, callback surfaces, delegation, and interactions with attacker-controlled contracts or tokens.

---

## What To Trace

- every `call`, `delegatecall`, low-level token transfer, and hook-capable interaction
- functions that call out before finalizing balances, shares, debt, or permissions
- callback-capable standards such as ERC777, ERC721, ERC1155, flash-loan hooks, and custom receiver interfaces
- paths where one function can reenter a related function instead of itself
- transient storage, low-gas callbacks, hook-based tokens, double-entry tokens, and flash-loan callback validation logic

---

## Commonly Missed

- CEI looks correct locally but another shared state path remains callable during callback
- `safeTransfer` or `transferFrom` is treated as side-effect free
- reentrancy guard applied to one entry point but not the paired settle/claim/withdraw path
- same `nonReentrant` guard suggested on a synchronous flash-loan or hook callback even though the outer entrypoint already holds the lock
- arbitrary target execution hidden behind adapters, plugins, vault hooks, or strategy contracts
- `delegatecall` used for extensibility without strict target control
- transient storage or per-transaction state used as a reentrancy boundary without proving it resets safely across nested calls and callbacks
- low-gas reentrancy assumptions where fallback, receive, ERC hooks, or token callbacks can still mutate the relevant state
- double-entry or wrapper-token flows where the apparent token transfer triggers a second asset movement or callback path
- flash-loan callbacks that validate the initiator but not the asset, amount, fee, pool, route, receiver, or final invariant

---

## Audit Questions

- Does any external interaction happen before all critical state is committed?
- Can attacker-controlled token behavior reopen the flow?
- Can a callback alter allowance, debt, collateral, or reward state before settlement finishes?
- Can a strategy, adapter, or plugin execute arbitrary code in protocol context?
- Can flash liquidity produce a temporary invariant violation long enough to profit?
- Does transient or per-transaction state remain correct through nested calls, revert paths, multicall, and callback ordering?
- Can a low-gas, hook, or double-entry-token path mutate accounting even though ordinary ERC20 transfer assumptions look safe?
- Does the flash-loan callback prove the full expected context, or only that some trusted lender called back?

---

## Shape Hint: External Code Before Settlement

```solidity
// Pseudo-shape only, not a signature.
function exit(uint256 shares) external {
    uint256 assets = previewRedeem(shares);
    token.safeTransfer(msg.sender, assets);
    _burn(msg.sender, shares);
}
```

Do not report by matching this shape alone. Confirm attacker-controlled code can execute before balances, shares, debt, permissions, or phase state are finalized; trace the reachable reentry or callback path; account for existing guards and settlement ordering; and show repeat withdrawal, stale accounting, under-collateralization, privilege change, or liveness impact.

---

## Success Signals For Findings

- repeated settlement from one initiating action
- double-withdraw, double-claim, or under-collateralized borrow
- stale state consumed after callback mutation
- protocol context executing attacker-chosen logic
- transient guard bypass through nested callback or multicall ordering
- flash-loan callback accepted with wrong asset, pool, route, or final balance
- low-gas or hook path changing state that the protocol treated as inert

---

## Remediation Notes

- Before recommending `nonReentrant`, trace whether the vulnerable callback is invoked synchronously from an outer function that already uses the same guard.
- If the callback is part of the intended happy path, reusing the same guard can self-revert the protocol instead of safely fixing the bug.
- Do not rely on gas stipend, transient storage, or a single initiator check as the complete fix unless the exploit path proves those controls cover nested calls, callbacks, and revert ordering.
- Prefer one of these minimal-fix patterns when they preserve behavior:
  - remove ETH/token payout from the callback and let the user pull funds later
  - move payout until after the callback-sensitive settlement window closes
  - add a dedicated callback-only guard or phase flag that blocks nested callback entry without blocking the initial flash-loan hook
- State the concrete impossible condition after the fix, such as: "user-controlled code can no longer run before flash-loan settlement completes."
