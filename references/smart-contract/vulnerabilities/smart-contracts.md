# Smart Contract Security Overview

This file is the compact overview for the smart-contract knowledge domain.

Smart contract review should treat contract code, off-chain signers, upgrade infrastructure, price dependencies, frontend-assisted signing, and token behavior as one trust system. The biggest misses are usually not syntax bugs but unsafe assumptions about business logic, external calls, privileged roles, accounting, market conditions, and the path that turns a user or admin signature into on-chain authority.

---

## Shape Hint Rule

Contract snippets in these modules are pseudo-shapes, not signatures. Do not report by matching shape alone, and do not clear a surface because it looks different. Confirm attacker-controlled execution or value influence, the broken invariant or authority boundary, the reachable transaction path, missing controls, and the concrete asset, authority, or liveness impact.

---

## What To Enumerate First

1. all privileged roles: owner, admin, upgrader, pauser, rescuer, keeper, signer
2. compiler reality: `pragma`, actual build compiler, optimizer settings, and imported dependency versions
3. every external call path, callback surface, and token transfer hook
4. accounting-critical state: balances, shares, exchange rates, debt, collateral, reward indices
5. oracle and pricing sources, especially spot-price or pool-reserve dependencies
6. upgrade paths: proxy admin, initializer, reinitializer, implementation auth
7. signature-based flows: permit, meta-transactions, approvals, off-chain orders
8. off-chain surfaces that can directly change on-chain authority: multisig UI, signer devices, deployment scripts, CI secrets, RPC endpoints, relayers, keepers, and upgrade pipelines

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
- algorithm or math-library defects in AMM, DEX, lending, or bridge logic where one bit shift, overflow check, or rounding branch can violate the whole pool invariant
- frontend, supply chain, or signer-compromise paths that induce valid multisig, proxy-admin, permit, or upgrade transactions with malicious semantics

---

## Commonly Missed Cases

- ERC777 / ERC721 / ERC1155 callbacks reopening a path that looked CEI-safe
- flash-loan-capable attackers forcing temporary invariant violations
- upgradeable deployments where constructor assumptions were never moved to `initialize`
- permit implementations that accept cross-chain or cross-contract replay
- admin timelock or multisig assumptions that are not actually enforced on-chain
- proxy + implementation storage collisions after upgrades
- custom pause, rescue, or recovery flows treated as "safe exits" even though they accept fresh assets or create new pending exposure
- prior-finding remediations that updated one helper but left sibling helpers on stale dust-threshold, min-out, or rounding rules
- remediation assumes a newer compiler feature or OZ helper than the repo actually builds with
- multisig or hardware-wallet quorum treated as sufficient even when signers cannot verify the actual calldata, target, implementation, or token movement they are approving
- frontend or deployment tooling ignored even though it constructs upgrade, permit, bridge, batch-swap, or admin transactions that move contract assets
- private-key or signer compromise dismissed as "operational" even when the contract has no delay, circuit breaker, revocation, or on-chain blast-radius limit

---

## Audit Questions

- Can any privileged action be called before initialization or by the wrong role?
- Can an external call reenter before state is finalized?
- What assumptions does accounting make about token behavior, decimals, or price freshness?
- Can an attacker move market state just long enough to profit from mint, borrow, liquidate, or redeem?
- Are signatures bound to nonce, domain, chain, contract, caller, and expiry?
- Can upgrade, pause, rescue, or recovery paths bypass normal user protections?
- Can compromised frontend, deployment, signer, or relayer infrastructure turn into a valid on-chain transaction that drains, upgrades, pauses, or reconfigures the protocol?
- Does any business-logic or algorithmic assumption depend on a math library, bit operation, pool invariant, or off-chain transaction builder that was not reviewed?
- If a prior issue was remediated, did every current helper that encodes the same invariant or trust boundary actually change?

---

## Grep Starting Points

```bash
rg -n "delegatecall|call\\{|call\\(|tx\\.origin|initializer|reinitializer|upgradeTo|upgradeToAndCall|onlyOwner|AccessControl|DEFAULT_ADMIN_ROLE" .
rg -n "transfer\\(|transferFrom\\(|safeTransfer\\(|onERC721Received|tokensReceived|flashLoan|executeOperation|callback" .
rg -n "oracle|TWAP|price|reserve|spot|sqrtPrice|latestRoundData|consult|quote" .
rg -n "permit|ecrecover|nonces|DOMAIN_SEPARATOR|EIP712|abi\\.encodePacked|signature" .
rg -n "for \\(|while \\(|claim|redeem|withdraw|liquidate|mint|burn|exchangeRate|shares|assets" .
rg -n "Safe|multisig|ProxyAdmin|upgrade|relayer|keeper|batchSwap|flashLoan|shift|shl|shr|mulDiv|sqrt|invariant" .
```

---

## Review Strategy

1. Map privileged roles and every state-changing entry point.
2. Pin the actual compiler and dependency reality before proposing exploitability or remediation conclusions.
3. Trace external calls and callback-capable token interactions.
4. Reconstruct core invariants for balances, shares, collateral, and debt.
5. Test whether pricing, signatures, math libraries, or upgrades can break those invariants under adversarial timing.
6. For DeFi, DEX, lending, bridge, cross-chain, upgradeable, Safe/multisig, frontend-assisted signing, or relayer-heavy systems, include signer, frontend, supply chain, and deployment trust only where they can affect assets, authority, signatures, or upgrades.
7. Separate pure code bugs from economic, governance, signer, frontend, supply chain, or deployment trust failures in reporting.

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
