# Deep Mode

High-assurance exhaustive audit mode.

---

## Scope

Run the primary-domain audit with maximum practical depth, then extend into attack chains, workflow abuse, data-flow tracing, and concurrency analysis.

Use when:
- the target is high value
- you need stronger assurance than standard mode
- attack chains, version drift, business logic, and state integrity matter

Report style is independent from deep-mode scan depth:
- `governance` keeps deep output root-cause-first for long-term remediation governance
- `exploit-first` makes the most dangerous exploit paths headline findings when that improves operator clarity
- `both` emits both concrete styles after one deep audit

---

## Required Load

- everything required by `modes/standard.md`
- `references/shared/dependencies/sca-integration.md` whenever external SCA data exists or dependency results come from non-native tooling
- additional specialist modules whenever the surface suggests deeper analysis
- exploit playbooks for verified or strongly suspected findings that need safe confirmation

---

## Recon Depth

Deep mode includes standard recon plus:
- trust-boundary mapping
- data-lifecycle mapping from input to storage to output to deletion
- stronger review of version drift, legacy paths, and alternate transports

---

## Scan Depth

- execute the primary domain audit path from `SKILL.md`
- trace sensitive inputs and control paths more exhaustively
- review compound risks across modules and versions
- apply finding boundaries through the active report style:
  - `governance` may merge same-root-cause exploit paths when remediation and trust boundary are materially shared
  - `exploit-first` should split operator-significant exploit paths while preserving cross-links to the shared root cause
- run native dependency audit commands for detected ecosystems, then review transitive, runtime, and base-image exposure where feasible

If the active profile is `smart-contract`, make `references/smart-contract/index.md` the main audit methodology and deepen exploit-path, accounting, signature, upgrade, oracle, and economic-abuse analysis instead of preserving a web-style category cadence.

If the active profile is `artifact-centric`, make instruction integrity, trust-boundary abuse, rendering risk, secret leakage, and environment drift the dominant deep-review themes.

After category coverage, perform:
- full attack-chain analysis
- exhaustive business-logic review
- deeper data-flow tracing
- full race-condition review
- API-specific depth checks

---

## Progress Labels

Deep mode uses the shared 6-step progress display from `SKILL.md`, but stages `3/6` to `5/6` now come from the active target profile:

- `profiles/application.md`
- `profiles/smart-contract.md`
- `profiles/artifact-centric.md`

These labels should replace the neutral placeholder labels only after recon, before stage `3/6` starts.

---

## Coverage Requirement

Use `references/shared/reporting/coverage-matrix.md` for the application domain.

If the active domain is `smart-contract`, use `references/smart-contract/vulnerabilities/coverage.md` instead.

Deep mode is complete when:
- for the application domain: all applicable categories reach covered status
- for the smart-contract domain: all applicable contract surfaces reach covered status
- no applicable category or domain surface remains shallow without an explicit blocker
- templates, API versions, config files, and trust boundaries are all reviewed when the active domain is application
- dependency review includes transitive risk where feasible
- infrastructure configs are reviewed line by line when present

---

## Output

- terminal summary
- full history file in `.security-code-audit-reports/`
- stronger historical context
- detailed attack-chain section or appendix
- `Working Hypotheses` appendix when unresolved material chains, trust assumptions, or shared-root-cause models remain after verification
- prioritized action items with compound-risk awareness

If `both` is selected, emit two deep reports from the same timestamp family rather than one blended report.
