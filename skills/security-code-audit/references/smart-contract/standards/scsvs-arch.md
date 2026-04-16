# SCSVS Architecture Mapping

Use this file to map contract-architecture checks from SCSVS-style review language into the current smart-contract audit domain.

This file is an overlay. It should help translate the existing audit methodology into standards language without pretending that every checklist item already has a one-to-one module.

---

## SCSVS-ARCH-1

| Item | Status | Primary Modules | Notes |
|---|---|---|---|
| `S1.1.A1` modularity and upgradability | `Partial` | `smart-contracts.md`, `upgradeability-and-deployment.md` | Upgradability is explicit; modularity and contract separation are reviewed indirectly, not through a dedicated architecture module. |
| `S1.1.A2` secure and controlled updates | `Explicit` | `upgradeability-and-deployment.md`, `trust-and-privilege.md` | Proxy patterns, upgrade auth, init reachability, and deployment sequencing are covered directly. |
| `S1.1.A3` module boundaries and dependencies | `Partial` | `smart-contracts.md`, `trust-and-privilege.md` | Interface boundaries and module contracts are touched indirectly, but not as a dedicated dependency-boundary review. |
| `S1.1.A4` storage-variable change management | `Partial` | `upgradeability-and-deployment.md` | Storage layout risk is explicit; storage gaps and documented layout discipline are not yet a dedicated checklist. |
| `S1.1.A5` critical privilege transfers | `Partial` | `trust-and-privilege.md`, `languages/solidity.md` | Ownership/admin rotation is covered; two-step transfer and critical event expectations are now explicit review items, but broader fallback handling remains partial. |
| `S1.1.A6` data location handling in overrides | `Gap` | `languages/solidity.md` | The current skill does not yet provide a dedicated checklist for override/data-location correctness. |
| `S1.1.B1` separation of responsibilities | `Partial` | `smart-contracts.md` | Single-responsibility and module split are considered indirectly, not as a standalone architecture control. |
| `S1.1.B2` minimal dependencies between modules | `Partial` | `smart-contracts.md`, `trust-and-privilege.md` | Tight coupling is noticed during review, but there is no explicit low-coupling checklist. |
| `S1.1.B3` cross-module dependency risk | `Partial` | `external-calls-and-reentrancy.md`, `upgradeability-and-deployment.md` | Risky cross-module execution paths are covered, but broad architecture dependency review is still implicit. |
| `S1.1.B4` consistent operation during privilege transfers | `Partial` | `trust-and-privilege.md` | Privilege rotation risk is covered, but transfer-failure edge cases and fallbacks are not yet explicit checklist items. |
| `S1.1.B5` proxy initialization | `Partial` | `upgradeability-and-deployment.md`, `trust-and-privilege.md` | Init/reinit risk is covered directly; `onlyInitializing` is not yet called out explicitly. |
| `S1.1.B6` storage layout consistency | `Explicit` | `upgradeability-and-deployment.md` | Storage layout delta and upgrade compatibility are first-class concerns. |
| `S1.1.B7` immutable variable consistency | `Partial` | `languages/solidity.md` | `immutable` is recognized as version-sensitive syntax, but upgrade consistency is not yet a dedicated deep-dive item. |
| `S1.1.B8` consistency in logic implementation | `Gap` | `smart-contracts.md` | General logic consistency is reviewed indirectly through invariants, but there is no explicit architecture-consistency checklist. |
| `S1.1.B9` separate handling of ETH and WETH | `Partial` | `external-calls-and-reentrancy.md`, `accounting-and-precision.md` | ETH/WETH semantics often surface during call and accounting review, but not yet as an explicit standard item. |
| `S1.1.B10` proxy setup for constructor-based contracts | `Explicit` | `upgradeability-and-deployment.md`, `trust-and-privilege.md` | Constructor-to-initializer migration and init sequencing are covered directly. |

---

## SCSVS-ARCH-2

| Item | Status | Primary Modules | Notes |
|---|---|---|---|
| `S1.2.A1` implementation of upgrade mechanisms | `Explicit` | `upgradeability-and-deployment.md` | Proxy types, upgrade flows, and auth paths are first-class review surfaces. |
| `S1.2.A2` safeguards against unauthorized upgrades | `Explicit` | `upgradeability-and-deployment.md`, `trust-and-privilege.md` | Upgrade auth and admin authority are covered directly. |
| `S1.2.A3` review and documentation of upgrade mechanism | `Partial` | `upgradeability-and-deployment.md` | The skill reviews upgrade design, but project-side documentation quality is not yet a dedicated checklist. |
| `S1.2.A4` immutable variable consistency | `Partial` | `languages/solidity.md` | Compiler-level `immutable` context is recognized; cross-version immutable validation is not yet explicit. |
| `S1.2.A5` `selfdestruct` and `delegatecall` in proxy setup | `Partial` | `languages/solidity.md`, `external-calls-and-reentrancy.md`, `smart-contracts.md` | `delegatecall` is explicit; `selfdestruct` is grep-visible but not yet a dedicated upgrade-control checklist item. |
| `S1.2.A6` protect UUPSUpgradeable contracts | `Partial` | `upgradeability-and-deployment.md`, `trust-and-privilege.md` | Init and upgrade auth risks are covered, but UUPS-specific helper expectations are not yet called out by name. |
| `S1.2.B1` handling of deprecated contract versions | `Gap` | `upgradeability-and-deployment.md` | Deprecated-version handling is not yet a dedicated contract-standard item. |
| `S1.2.B2` restrict deprecated versions | `Gap` | `upgradeability-and-deployment.md` | Same as above; partially related to upgrade and admin review, but not explicit today. |
| `S1.2.B3` migration paths from deprecated versions | `Partial` | `upgradeability-and-deployment.md` | Migration and rollout risk are covered generally, but deprecated-version migration is not yet explicit. |

---

## SCSVS-ARCH-3

| Item | Status | Primary Modules | Notes |
|---|---|---|---|
| `S1.3.C1` high-priority mitigations | `Explicit` | `trust-and-privilege.md`, `external-calls-and-reentrancy.md`, `accounting-and-precision.md`, `upgradeability-and-deployment.md` | Reentrancy, access control, arithmetic, and initialization risks are first-class review surfaces. |
| `S1.3.C2` documentation and testing of mitigations | `Partial` | `coverage.md`, `shared/reporting/*` | The skill evaluates mitigation quality and reportability, but does not yet provide a dedicated contract-mitigation testing checklist. |
| `S1.3.C3` validation of mitigation effectiveness | `Partial` | `coverage.md`, `shared/reporting/history-standard.md`, `shared/reporting/regression-standard.md` | Regression and coverage review help here, but periodic audit/monitoring expectations are not fully contract-specific today. |

---

## Practical Reading

The current contract methodology is strong on:
- privilege and initialization risk
- external calls, callbacks, and reentrancy
- accounting and arithmetic-driven exploitability
- oracle and flash-loan-assisted profit paths
- proxy and upgradeability risk

The most visible architecture gaps today are:
- dedicated module-boundary and modularity review
- explicit override/data-location checks
- explicit deprecated-version handling
- explicit ETH/WETH separation as a standards item
- explicit storage-gap / `onlyInitializing` / two-step ownership checklist language

Use `Partial` and `Gap` honestly. This overlay is meant to expose missing standard coverage, not hide it.
