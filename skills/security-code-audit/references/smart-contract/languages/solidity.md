# Solidity Security Checklist

Use this file when the repo contains `.sol` contracts, Foundry, Hardhat, or on-chain/off-chain trust logic. Solidity review is less about classic web sinks and more about call boundaries, privileged roles, accounting, signatures, upgradeability, and market assumptions.

---

## Version-Aware Review

Always identify three things before trusting a remediation or dismissing a pattern:
- the source `pragma` range in each contract
- the actual compiler version selected by Foundry, Hardhat, or CI
- the imported dependency version, especially OpenZeppelin upgrade and access-control helpers

Do not assume these are the same. A repo can declare a broad pragma but compile with one pinned version, and library availability can differ again.

Use this context to sharpen conclusions, not to suppress them automatically. Compiler reality should improve exploitability and remediation accuracy; it should not become a blanket excuse to ignore a suspicious pattern.

Version-sensitive reminders:
- pre-`0.8.x` arithmetic does not revert on overflow/underflow by default; remediation and exploitability differ sharply from `0.8.x`
- `receive()` / `fallback()` semantics changed in the `0.6.x` era; do not recommend modern ETH-handling patterns without checking target compiler behavior
- features such as custom errors, `unchecked`, `immutable`, `try/catch`, and `abi.encodeCall` are compiler-generation dependent; do not suggest them blindly
- randomness and entropy guidance depends on chain and compiler era: `block.difficulty` vs `block.prevrandao` is not interchangeable advice
- OpenZeppelin helpers such as `Ownable2Step`, newer upgrade base contracts, or specific guard utilities depend on the imported OZ release, not just the Solidity pragma

If the safest remediation needs a compiler or dependency bump, say so explicitly instead of presenting it as a local one-line patch.

---

## Key Risk Families

### External Calls and Reentrancy
- state updates after `call`, `delegatecall`, token transfer hooks, or arbitrary external interaction
- callbacks hidden behind ERC777, ERC721 receiver hooks, flash-loan callbacks, or user-supplied target contracts

### Access Control
- missing `onlyOwner` / role checks
- privileged functions reachable before initialization
- `tx.origin` used for auth
- upgrade, pause, mint, withdraw, or rescue functions with weak caller restrictions

### Accounting and Precision
- share inflation, rounding drift, stale accounting snapshots
- price or exchange-rate logic that trusts manipulable on-chain state
- unchecked assumptions around fee-on-transfer, rebasing, or non-standard ERC20 behavior

### Signatures and Replay
- missing nonces, domain separation, expiry, or chain binding
- unsafe `permit`, custom meta-transactions, or off-chain approvals

### Upgradeability and Delegation
- unprotected initializer or reinitializer
- arbitrary `delegatecall`
- storage slot collisions and upgrade auth failures

### Oracle, MEV, and DoS
- spot-price oracle trust
- flash-loan-assisted state changes
- gas griefing, unbounded loops, and liveness failures
- weak randomness based on block values

---

## Commonly Missed

- CEI broken indirectly by hook-based tokens
- `safeTransfer` assumed to be safe when downstream code is still reentrant
- role admin paths forgotten during proxy upgrades
- pragma range, actual compiler, and imported OZ version silently diverge, so the suggested fix does not compile or changes semantics
- `abi.encodePacked` collisions in signature or authorization schemes
- chain-specific assumptions missing from signed payloads
- admin rescue functions that can drain user funds or bypass accounting

---

## Grep Starting Points

```bash
rg -n "delegatecall|call\\{|call\\(|staticcall|selfdestruct|tx\\.origin|ecrecover|permit|DOMAIN_SEPARATOR|initializer|reinitializer|onlyOwner|AccessControl|unchecked" .
rg -n "transfer\\(|transferFrom\\(|safeTransfer\\(|safeTransferFrom\\(|onERC721Received|tokensReceived|flashLoan|swap|oracle|price" .
rg -n "block\\.timestamp|blockhash|block\\.prevrandao|keccak256\\(abi\\.encodePacked" .
rg -n "for \\(|while \\(|mapping|totalSupply|shares|assets|exchangeRate|previewMint|previewRedeem" .
```

---

## Related References

- `references/smart-contract/index.md`
- `references/smart-contract/vulnerabilities/accounting-and-precision.md`
- `references/smart-contract/vulnerabilities/signatures-and-meta-transactions.md`
- `references/smart-contract/vulnerabilities/oracle-mev-and-market-abuse.md`
- `references/smart-contract/vulnerabilities/upgradeability-and-deployment.md`
- `references/smart-contract/vulnerabilities/smart-contracts.md`
- `references/smart-contract/exploits/smart-contracts.md`
