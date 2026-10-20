# Smart-Contract Coverage Standard

Use this file instead of the generic application `coverage-matrix.md` when the active knowledge domain is `smart-contract`.

Its job is to verify that the audit really covered contract-native risk, not just a handful of Solidity grep hits.

---

## Coverage Matrix

| Surface | Key Questions | Covered? | Findings |
|---------|---------------|----------|----------|
| Trust And Privilege | All owner/admin/upgrader/signer roles mapped? Init/reinit paths reviewed? Rescue, pause, sweep, queue, claim, and governance assumptions checked? Critical privilege transitions emit monitorable events? Entry-like emergency paths distinguished from true exits? Any `msg.value`-accepting or request-creating emergency helper reviewed as entry-like rather than auto-whitelisted as an exit? | | |
| Authorization And Asset Flow | For every privileged or semi-privileged entry point, is the `(caller, action, token, source, recipient, spender, route, amount, state key, phase)` capability tuple checked? Are role checks separated from destination, allowance, selector, and downstream strategy constraints? | | |
| External Calls And Reentrancy | All external calls traced? Callback-capable token and receiver flows reviewed? Related-function reentrancy considered? Delegation and arbitrary target execution checked? Is every cooldown, nonce, limit, or phase write ordered before the callback-sensitive call? | | |
| Cross-Contract Integration And Settlement | Do interface, adapter, solver, vault, and strategy traces verify gross/net, fees, decimals, actual balance deltas, min-out, deadlines, recipient binding, and mock/deployment semantic parity? | | |
| Accounting And Precision | Assets/shares/debt invariants reconstructed? Rounding direction reviewed? Fee-on-transfer, rebasing, decimals, bootstrap, donation, and low-liquidity edge cases checked? Sibling helpers reviewed for post-fix threshold or rounding drift across open/manage/exit paths? | | |
| State Keying, Limits And Replay | Are allowances, cooldowns, rate limits, nonces, replay guards, and settlement records keyed by every policy dimension such as token, spender, user, route, and intent? Are reset, revocation, expiry, multicall, and sibling paths consistent? | | |
| Execution Context And Capability Lifecycle | For delegatecall/proxy/plugin/CPI/registry boundaries, are original caller, execution context, selected target, selector/instruction, and final asset account bound together? Do remove/quarantine/disable/supported flags revoke or gate stale allowances and every sibling execution path? | | |
| Signatures And Meta-Tx | Permit, EIP-712, relayer, and signer paths mapped? Nonce, expiry, chain, domain, beneficiary, and replay protections verified? | | |
| Oracle / Market Abuse | Price source, freshness, manipulation resistance, liquidation math, and same-tx reserve dependence reviewed? Economic exploit path considered? | | |
| Upgradeability And Deployment | Proxy type identified? Upgrade auth and init reachability reviewed? Storage-layout risk considered? Deployment and environment assumptions checked? | | |
| Token Integration Semantics | ERC20/777/721/1155 behavior assumptions reviewed? Non-standard return values, hooks, and transfer semantics handled safely? | | |
| Supporting Shared Surfaces | Dependency/tooling, infrastructure, config, logging/monitoring, signer/frontend/supply chain trust reviewed where present? Command resolution applied before optional tools such as Foundry/Hardhat scripts, Slither, Mythril, dependency scanners, or IaC/container scanners? | | |

---

## Coverage Standards

- **Mandatory**: Trust And Privilege, Authorization And Asset Flow, External Calls And Reentrancy, Accounting And Precision, and Signatures And Meta-Tx
- **Mandatory when applicable**: Cross-Contract Integration And Settlement and State Keying, Limits And Replay for any adapter, solver, strategy, allowance, cooldown, rate-limit, or intent flow
- **Mandatory when applicable**: Execution Context And Capability Lifecycle for any delegatecall, proxy/plugin, registry/CPI, remove-token, quarantine, revoke, or supported-flag flow
- **Mandatory when applicable**: Oracle / Market Abuse for any price-sensitive or liquidity-sensitive protocol
- **Mandatory when applicable**: Upgradeability And Deployment for any proxy, factory, clone, beacon, or staged deployment system
- **Mandatory when applicable**: Token Integration Semantics when integrating external tokens or token standards beyond trivial fixed-behavior assumptions
- **Mandatory**: Supporting shared surfaces whenever manifests, CI/deployment config, signer env, frontend transaction builders, Safe/multisig apps, relayers, keepers, RPC config, or operational infrastructure can affect contract assets, authority, signatures, or upgrades
- **Mandatory**: Security-relevant contract functions and privileged state transitions must have bounded function-chain records or explicit coverage debt

---

## Termination Criteria

### Quick Audit

- privilege and init risk triaged
- external-call and callback paths triaged
- obvious accounting or signature red flags checked
- high-risk exploit path documented when present
- signer, frontend, supply chain, or ProxyAdmin trust triaged when it can directly affect assets or upgrades

### Standard Audit

- all mandatory contract surfaces covered
- any omitted optional surface has explicit written justification
- at least one invariant-oriented accounting review completed
- exploitability described in code and economic terms where relevant
- signer/frontend/supply chain assumptions documented for any Safe/multisig, upgradeable, relayer, bridge, or admin-heavy protocol
- counted coverage totals reconciled and bounded function-chain records captured for in-scope contract functions

### Deep Audit

- all applicable surfaces covered
- every applicable high-risk smart-contract surface has a reconciled deep semantic gate in audit state, especially oracle, accounting, signature, upgrade, token integration, and multi-contract trust surfaces
- accounting model reconstructed end to end
- attacker profit path analyzed for market-sensitive findings
- deployment, upgrade, signer, and off-chain trust assumptions reviewed in detail
- frontend-assisted signing, supply chain to signature, and ProxyAdmin blast-radius controls reviewed when present
- compound exploit paths documented where they materially change impact
- every in-scope privileged, accounting, signature, call, or upgrade function has a bounded function-chain record or explicit coverage debt
- every in-scope capability tuple and integration assumption has a bounded trace, deep gate, or explicit coverage debt
- every callback-sensitive state transition records pre-call/post-call ordering, and every delegation or lifecycle boundary records target binding and stale-authority behavior
