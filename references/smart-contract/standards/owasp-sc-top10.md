# OWASP Smart Contracts Top 10 Mapping

Use this file to map the current smart-contract audit domain to OWASP Smart Contracts Top 10 terminology.

This file does not redefine the audit flow. It explains how the existing contract modules line up with the OWASP categories.

---

## Coverage Map

| OWASP Item | Status | Primary Modules | Notes |
|---|---|---|---|
| `SC01:2026 Access Control Vulnerabilities` | `Explicit` | `trust-and-privilege.md`, `upgradeability-and-deployment.md` | Owner/admin/upgrader/signer authority, init auth, rescue, and privileged state transitions are first-class review surfaces. |
| `SC02:2026 Business Logic Vulnerabilities` | `Partial` | `smart-contracts.md`, `accounting-and-precision.md`, `oracle-mev-and-market-abuse.md`, `external-calls-and-reentrancy.md` | Business logic is covered through invariants, attacker profit paths, and sequencing review, but there is no standalone contract-business-logic module yet. |
| `SC03:2026 Price Oracle Manipulation` | `Explicit` | `oracle-mev-and-market-abuse.md` | Oracle trust, stale pricing, same-tx reserve shaping, and market-abuse profit paths are covered directly. |
| `SC04:2026 Flash Loan–Facilitated Attacks` | `Explicit` | `external-calls-and-reentrancy.md`, `oracle-mev-and-market-abuse.md` | Flash-loan-assisted invariant breaks and same-transaction manipulation are part of the contract review path. |
| `SC05:2026 Lack of Input Validation` | `Partial` | `trust-and-privilege.md`, `accounting-and-precision.md`, `signatures-and-meta-transactions.md`, `smart-contracts.md` | Semantic input validation is covered where it affects auth, accounting, signatures, or profit paths, but there is no standalone input-validation deep dive today. |
| `SC06:2026 Unchecked External Calls` | `Explicit` | `external-calls-and-reentrancy.md` | External calls, callbacks, delegation, and related-function reentrancy are covered directly. |
| `SC07:2026 Arithmetic Errors` | `Explicit` | `accounting-and-precision.md`, `languages/solidity.md` | Arithmetic correctness is handled through invariant review, rounding, decimals, and compiler-version-aware semantics. |
| `SC08:2026 Reentrancy Attacks` | `Explicit` | `external-calls-and-reentrancy.md` | Direct, indirect, callback, and related-function reentrancy are covered explicitly. |
| `SC09:2026 Integer Overflow and Underflow` | `Partial` | `languages/solidity.md`, `accounting-and-precision.md` | Covered through Solidity version-aware review and arithmetic/invariant analysis, but not yet as a dedicated overflow/underflow module. |
| `SC10:2026 Proxy & Upgradeability Vulnerabilities` | `Explicit` | `upgradeability-and-deployment.md`, `trust-and-privilege.md` | Proxy type, initializer reachability, upgrade auth, storage layout, and deployment sequencing are direct audit surfaces. |

---

## Interpretation Notes

- `Explicit` means the item has a dedicated contract module or a first-class place in the domain spine.
- `Partial` means the item is reviewed today, but coverage is spread across multiple modules or lacks a dedicated checklist.
- The main current gaps for cleaner OWASP alignment are:
  - a dedicated contract `business logic` module
  - a dedicated contract `input validation` module
  - a more explicit contract `overflow / underflow` module beyond version-aware Solidity review

---

## Recommended Use

When reporting against OWASP Smart Contracts Top 10:
1. start from the actual technical modules in `references/smart-contract/vulnerabilities/`
2. use this mapping only to translate findings and coverage into OWASP labels
3. do not claim full support for `Partial` items without project-specific additional review
