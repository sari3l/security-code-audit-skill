# Smart-Contract Vulnerability Index

Use this index as the main methodology map for Solidity and contract-heavy audits.

The files in this directory are ordered to match how contract review should usually progress: trust first, then call boundaries, then accounting, signatures, oracle assumptions, upgradeability, and final coverage.

---

## Module Map

- `references/smart-contract/vulnerabilities/smart-contracts.md`
  Compact domain overview and first-pass audit map.

- `references/smart-contract/vulnerabilities/trust-and-privilege.md`
  Owners, roles, initialization, rescue flows, governance, and privileged trust boundaries.

- `references/smart-contract/vulnerabilities/external-calls-and-reentrancy.md`
  External calls, callbacks, delegation, flash-loan-assisted flows, and execution ordering.

- `references/smart-contract/vulnerabilities/accounting-and-precision.md`
  Share math, exchange rates, rounding, fee-on-transfer, rebasing, and invariant review.

- `references/smart-contract/vulnerabilities/signatures-and-meta-transactions.md`
  Permit, EIP-712, replay, relayers, nonce handling, and signer intent.

- `references/smart-contract/vulnerabilities/oracle-mev-and-market-abuse.md`
  Oracle trust, price manipulation, timing, MEV, liquidation abuse, and attacker profit paths.

- `references/smart-contract/vulnerabilities/upgradeability-and-deployment.md`
  Proxy patterns, init sequencing, storage layout, deployment assumptions, and admin operations.

- `references/smart-contract/vulnerabilities/coverage.md`
  Domain-specific coverage expectations for contract audits.

---

## Loading Guidance

1. Start with `smart-contracts.md`.
2. Load the deep dives that match the observed surface.
3. Load `coverage.md` near stage `5/6` and final report generation.
