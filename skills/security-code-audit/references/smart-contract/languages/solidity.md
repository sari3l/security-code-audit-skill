# Solidity Security Checklist

Use this file when the repo contains `.sol` contracts, Foundry, Hardhat, or on-chain/off-chain trust logic. Solidity review is less about classic web sinks and more about call boundaries, privileged roles, accounting, signatures, upgradeability, and market assumptions.

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
