# Smart-Contract Profile

Use this profile when the repo is primarily Solidity or contract-heavy logic.

The visible progress should reflect contract trust boundaries, accounting, signatures, upgradeability, deployment assumptions, and economic abuse rather than a generic web Top 10 sweep.

---

## Progress Labels

### Quick

- `[3/6] Triage contract trust, call, and privilege surfaces`
- `[4/6] Check accounting, dependency, and deployment red flags`
- `[5/6] Minimal exploit validation, history, and report prep`

### Standard

- `[3/6] Audit contract trust, call, and privilege surfaces`
- `[4/6] Audit accounting, signature, dependency, and deployment surfaces`
- `[5/6] Analyze exploit paths, economic abuse, and history`

### Deep

- `[3/6] Deep contract trust, call, and privilege analysis`
- `[4/6] Exhaustive accounting, signature, dependency, and deployment review`
- `[5/6] Attack paths, economic abuse, strict coverage, and history`

---

## Emphasis Notes

- privilege, initializer, and upgrade trust should appear early
- external calls, callbacks, reentrancy, and delegation should dominate control-surface review
- accounting, precision, permits, oracle assumptions, and deployment/proxy risk should dominate later stages
- post-category analysis should use exploit-path and economic-abuse language instead of generic business-logic phrasing
- when recon finds accounting/precision, permit/signature/meta-transaction, oracle/price, proxy/upgrade/initializer, or multi-contract delegation/callback trust surfaces, keep richer audit state and function-chain detail even if the repo is small

---

## Audit Routing

- use `references/smart-contract/index.md` as the primary audit domain router
- use `references/smart-contract/vulnerabilities/smart-contracts.md` as the compact domain overview
- use `references/smart-contract/languages/solidity.md` for grep starters, sink patterns, and code-shape hints
- use `references/smart-contract/exploits/smart-contracts.md` only when validation is needed
- treat shared categories such as authz, misconfiguration, dependencies, cryptography, logging, and infrastructure as supporting lenses, not the main narrative
- avoid presenting the audit as a generic injection/auth/authz/XSS sweep when the repo is primarily on-chain logic
