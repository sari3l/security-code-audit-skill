# Smart Contract Security Overview

This file is the compact overview for the smart-contract knowledge domain.

Smart contract review should treat contract code, off-chain signers, upgrade infrastructure, price dependencies, and token behavior as one trust system. The biggest misses are usually not syntax bugs but unsafe assumptions about external calls, privileged roles, accounting, and market conditions.

---

## What To Enumerate First

1. all privileged roles: owner, admin, upgrader, pauser, rescuer, keeper, signer
2. compiler reality: `pragma`, actual build compiler, optimizer settings, and imported dependency versions
3. every external call path, callback surface, and token transfer hook
4. accounting-critical state: balances, shares, exchange rates, debt, collateral, reward indices
5. oracle and pricing sources, especially spot-price or pool-reserve dependencies
6. upgrade paths: proxy admin, initializer, reinitializer, implementation auth
7. signature-based flows: permit, meta-transactions, approvals, off-chain orders

---

## High-Risk Patterns

- state written after external interaction, allowing reentrancy or callback abuse
- `tx.origin` used for auth or upgrade checks
- unprotected initializer, reinitializer, or upgrade function
- arbitrary `delegatecall`, user-supplied target, or unsafe plugin architecture
- spot-price oracle trust that can be manipulated in one transaction or one block
- share/accounting logic that rounds in the attacker's favor or ignores rebasing / fee-on-transfer behavior
- missing nonces, expiry, chain ID, or domain separation in signatures
- emergency or rescue functions that bypass user accounting and can drain locked funds
- unbounded iteration or gas-sensitive loops that can freeze redemptions, claims, or withdrawals
- weak randomness based on block timestamp, blockhash, or validator-influenced data

---

## Commonly Missed Cases

- ERC777 / ERC721 / ERC1155 callbacks reopening a path that looked CEI-safe
- flash-loan-capable attackers forcing temporary invariant violations
- upgradeable deployments where constructor assumptions were never moved to `initialize`
- permit implementations that accept cross-chain or cross-contract replay
- admin timelock or multisig assumptions that are not actually enforced on-chain
- proxy + implementation storage collisions after upgrades
- remediation assumes a newer compiler feature or OZ helper than the repo actually builds with

---

## Audit Questions

- Can any privileged action be called before initialization or by the wrong role?
- Can an external call reenter before state is finalized?
- What assumptions does accounting make about token behavior, decimals, or price freshness?
- Can an attacker move market state just long enough to profit from mint, borrow, liquidate, or redeem?
- Are signatures bound to nonce, domain, chain, contract, caller, and expiry?
- Can upgrade, pause, rescue, or recovery paths bypass normal user protections?

---

## Grep Starting Points

```bash
rg -n "delegatecall|call\\{|call\\(|tx\\.origin|initializer|reinitializer|upgradeTo|upgradeToAndCall|onlyOwner|AccessControl|DEFAULT_ADMIN_ROLE" .
rg -n "transfer\\(|transferFrom\\(|safeTransfer\\(|onERC721Received|tokensReceived|flashLoan|executeOperation|callback" .
rg -n "oracle|TWAP|price|reserve|spot|sqrtPrice|latestRoundData|consult|quote" .
rg -n "permit|ecrecover|nonces|DOMAIN_SEPARATOR|EIP712|abi\\.encodePacked|signature" .
rg -n "for \\(|while \\(|claim|redeem|withdraw|liquidate|mint|burn|exchangeRate|shares|assets" .
```

---

## Review Strategy

1. Map privileged roles and every state-changing entry point.
2. Pin the actual compiler and dependency reality before proposing exploitability or remediation conclusions.
3. Trace external calls and callback-capable token interactions.
4. Reconstruct core invariants for balances, shares, collateral, and debt.
5. Test whether pricing, signatures, or upgrades can break those invariants under adversarial timing.
6. Separate pure code bugs from economic, governance, or deployment trust failures in reporting.

---

## Smart-Contract Domain Deep Dives

- `references/smart-contract/index.md`
- `references/smart-contract/vulnerabilities/trust-and-privilege.md`
- `references/smart-contract/vulnerabilities/external-calls-and-reentrancy.md`
- `references/smart-contract/vulnerabilities/accounting-and-precision.md`
- `references/smart-contract/vulnerabilities/signatures-and-meta-transactions.md`
- `references/smart-contract/vulnerabilities/oracle-mev-and-market-abuse.md`
- `references/smart-contract/vulnerabilities/upgradeability-and-deployment.md`

---

## Related References

- `references/smart-contract/languages/solidity.md`
- `references/smart-contract/index.md`
- `references/smart-contract/exploits/smart-contracts.md`
