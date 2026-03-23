# Smart-Contract Coverage Standard

Use this file instead of the generic application `coverage-matrix.md` when the active knowledge domain is `smart-contract`.

Its job is to verify that the audit really covered contract-native risk, not just a handful of Solidity grep hits.

---

## Coverage Matrix

| Surface | Key Questions | Covered? | Findings |
|---------|---------------|----------|----------|
| Trust And Privilege | All owner/admin/upgrader/signer roles mapped? Init/reinit paths reviewed? Rescue, pause, sweep, and governance assumptions checked? | | |
| External Calls And Reentrancy | All external calls traced? Callback-capable token and receiver flows reviewed? Related-function reentrancy considered? Delegation and arbitrary target execution checked? | | |
| Accounting And Precision | Assets/shares/debt invariants reconstructed? Rounding direction reviewed? Fee-on-transfer, rebasing, decimals, bootstrap, donation, and low-liquidity edge cases checked? | | |
| Signatures And Meta-Tx | Permit, EIP-712, relayer, and signer paths mapped? Nonce, expiry, chain, domain, beneficiary, and replay protections verified? | | |
| Oracle / Market Abuse | Price source, freshness, manipulation resistance, liquidation math, and same-tx reserve dependence reviewed? Economic exploit path considered? | | |
| Upgradeability And Deployment | Proxy type identified? Upgrade auth and init reachability reviewed? Storage-layout risk considered? Deployment and environment assumptions checked? | | |
| Token Integration Semantics | ERC20/777/721/1155 behavior assumptions reviewed? Non-standard return values, hooks, and transfer semantics handled safely? | | |
| Supporting Shared Surfaces | Dependency/tooling, infrastructure, config, logging/monitoring, and off-chain trust reviewed where present? | | |

---

## Coverage Standards

- **Mandatory**: Trust And Privilege, External Calls And Reentrancy, Accounting And Precision, and Signatures And Meta-Tx
- **Mandatory when applicable**: Oracle / Market Abuse for any price-sensitive or liquidity-sensitive protocol
- **Mandatory when applicable**: Upgradeability And Deployment for any proxy, factory, clone, beacon, or staged deployment system
- **Mandatory when applicable**: Token Integration Semantics when integrating external tokens or token standards beyond trivial fixed-behavior assumptions
- **Mandatory**: Supporting shared surfaces whenever manifests, CI/deployment config, signer env, or operational infrastructure exist

---

## Termination Criteria

### Quick Audit

- privilege and init risk triaged
- external-call and callback paths triaged
- obvious accounting or signature red flags checked
- high-risk exploit path documented when present

### Standard Audit

- all mandatory contract surfaces covered
- any omitted optional surface has explicit written justification
- at least one invariant-oriented accounting review completed
- exploitability described in code and economic terms where relevant

### Deep Audit

- all applicable surfaces covered
- accounting model reconstructed end to end
- attacker profit path analyzed for market-sensitive findings
- deployment, upgrade, signer, and off-chain trust assumptions reviewed in detail
- compound exploit paths documented where they materially change impact
