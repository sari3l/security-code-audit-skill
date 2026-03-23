# Smart-Contract Security Domain

Use this domain when the repo is primarily Solidity or contract-heavy on-chain logic.

This domain exists because contract auditing is not a thin variant of web Top 10 review. It must center trust boundaries, privileged roles, external calls, token behavior, accounting, signatures, upgradeability, oracle assumptions, and attacker profit paths.

---

## Primary Entry Points

- `references/smart-contract/languages/index.md`
  Contract-language grep starters and sink reminders.

- `references/smart-contract/vulnerabilities/index.md`
  Main methodology map for trust, calls, accounting, signatures, oracle assumptions, and upgradeability.

- `references/smart-contract/exploits/index.md`
  Contract exploit validation guidance once a finding is verified or strongly suspected.

---

## Supporting Shared Modules

These remain relevant when the surface matches, but they are supporting lenses rather than the main audit spine:

- `references/shared/dependencies/index.md`
  Off-chain dependency, tooling, library, and supply-chain review.

- `references/application/vulnerabilities/infrastructure.md`
  Deployment, CI, IaC, signer, and environment exposure around the contract system.

- `references/application/vulnerabilities/configuration-files.md`
  `.env`, deployment scripts, RPC config, CI secrets, and release configuration.

- `references/application/vulnerabilities/logging-monitoring.md`
  Event coverage, admin observability, alertability, and incident response hooks.

- `references/shared/reporting/index.md`
  Findings, remediation, coverage, severity, and historical reporting standards.

---

## Required Mindset

- reconstruct invariants before chasing isolated patterns
- model attacker profit paths, not just code smell
- treat token semantics and market assumptions as part of the system
- separate code exploitability from economic feasibility, but capture both when relevant
- do not force contract review into an application-style category cadence

---

## Loading Guidance

1. Start with `references/smart-contract/vulnerabilities/index.md`.
2. Load `references/smart-contract/languages/index.md` when you need language-level grep starters or sink hints.
3. Pull in only the deep dives that match the observed trust, accounting, signature, oracle, or deployment surface.
4. Use `references/smart-contract/exploits/index.md` only when validation is needed.
5. Add `references/shared/` modules only when artifacts, dependencies, configuration, reporting, or history work actually require them.
