# Standard Mode

Default full audit mode.

---

## Scope

Run the primary-domain audit with practical depth, then perform basic compound analysis and coverage verification.

Standard mode is an independent fresh discovery audit, not a remediation-retest mode.
Do not inspect prior report details until the current standard-mode findings, coverage reconciliation, and audit-state writes are complete.

Use when:
- no specific mode is requested
- you want actionable findings with structured coverage
- you need historical comparison and a full report

---

## Required Load

- `references/application/languages/index.md`
- `references/application/frameworks/index.md`
- the active knowledge domain router after recon:
  - `references/application/index.md`
  - `references/smart-contract/index.md`
- `references/application/vulnerabilities/index.md` when the active domain is application or when a shared supporting category is needed
- `references/shared/dependencies/index.md` when manifests, lock files, vendored dependencies, or SCA artifacts are present
- relevant language and framework modules
- specialist vulnerability modules when the surface matches
- `references/shared/reporting/index.md`
- `references/shared/reporting/history-standard.md` for deferred post-scan comparison only
- `references/shared/reporting/coverage-matrix.md`

Use `references/application/exploits/index.md` only for verified or strongly suspected findings that need confirmation guidance.

---

## Recon Depth

In addition to the shared base recon in `SKILL.md`, standard mode requires:
- route and entry-point mapping
- API version enumeration
- sensitive-area mapping
- security config review
- business-logic surface mapping

---

## Scan Depth

- execute the primary domain audit path from `SKILL.md`
- enumerate repeated vulnerable patterns across the codebase
- group multiple downstream exploit paths into one finding only when the failed control, trust boundary, and minimal fix are materially shared
- surface operator-significant exploit paths clearly in the title, `Attack Vector`, `Impact`, `Related Findings`, or `Attack Chains` instead of splitting findings by default
- run native dependency audit commands for detected ecosystems when lock files/manifests exist, and document any tooling blockers instead of skipping C8

If the active profile is `smart-contract`, treat `references/smart-contract/index.md` as the primary audit spine and use only the shared categories that genuinely map to the contract trust model.

If the active profile is `artifact-centric`, center prompt, rendering, trust-boundary, sensitive-data, dependency, and environment review instead of forcing an application-style category order.

After category coverage, perform:
- basic compound finding analysis
- basic business-logic review
- basic race-condition review
- counted coverage reconciliation and bounded function-chain inventory review
- deferred history replay only after current findings and coverage are stable
- historical-miss gate first: reopen prior findings that touch the same current helper, sink, route family, or trust boundary and check whether any still-live path was missed by the current scan
- if any historical miss exists, record it, emit `Skill Optimization Suggestions`, and withhold lifecycle finalization
- only when no historical misses exist may the report finalize `New`, `Recurring`, `Regression`, or `Fixed since last scan`

---

## Progress Labels

Standard mode uses the shared 6-step progress display from `SKILL.md`, but stages `3/6` to `5/6` now come from the active target profile:

- `profiles/application.md`
- `profiles/smart-contract.md`
- `profiles/artifact-centric.md`

These labels should replace the neutral placeholder labels only after recon, before stage `3/6` starts.

---

## Coverage Requirement

Use `references/shared/reporting/coverage-matrix.md` for the application domain.

If the active domain is `smart-contract`, use `references/smart-contract/vulnerabilities/coverage.md` instead.

Standard mode is complete when:
- for the application domain: 10 out of 12 categories, or all applicable ones, are covered
- for the smart-contract domain: all mandatory contract surfaces are covered and any omitted optional surface has written justification
- template files and API versions are fully covered when the active domain is application
- critical and high findings have reproduction evidence
- audit state includes counted coverage totals and bounded function-chain records for all security-relevant functions in scope, or explicit coverage debt where that was not possible

---

## Output

- terminal summary
- full history file in `.security-code-audit-reports/`
- category or domain coverage
- counted coverage summary and function-chain section derived from audit state
- historical context
- prioritized action items
