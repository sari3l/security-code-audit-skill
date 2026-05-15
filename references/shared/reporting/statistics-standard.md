# Statistics Standard

Statistics should support triage and coverage, not just make the report look complete.

---

## Required Counts

- confirmed findings by severity using underlying fingerprint-backed issue counts
- findings by category or domain surface
- findings by status: new, recurring, regression, fixed since last scan, but only when the historical-miss gate passes
- historical miss count
- evidence observations by kind and routed/unrouted status when material
- schema gap count when nonzero
- candidate signal count
- coverage debt item count
- skill optimization suggestion count when historical misses exist
- applicable categories or domain surfaces by state: reviewed, partial, blocked, invalidated, time-boxed, not applicable
- security-relevant functions in scope vs function chains recorded
- explicit function-chain debt count, reconciled so `function_entries_total == function_chains_recorded + explicit_function_chain_debt`
- deep semantic gates by state when `deep` mode or beta `multi` used them: covered, partial, blocked, invalidated, not started
- open proof obligations by destination: finding, candidate signal, coverage debt, working hypothesis, integration assumption, none
- audit state quality gate status: pass, fail, or blocked
- current-change-context counts: changed files, changed shared surfaces, invalidated prior records, selective prior-state loads
- merge queue counts in beta `multi`: merged, rejected, routed, unresolved final-blocking
- number of API versions reviewed
- number of template/view files reviewed
- number of config and deployment files reviewed when present

---

## Useful Optional Metrics

- grouped finding count when one finding intentionally covers multiple downstream exploit paths under one remediation boundary
- number of endpoints audited
- number of affected endpoints for repeated patterns
- number of attack chains identified
- number of open working hypotheses in Deep or beta `multi` reports
- number of code fact limitations that became coverage debt
- number of agents contributing state in beta `multi`
- number of operational risks, integration assumptions, or engineering notes when these sections are present
- number of secrets or credentials exposed
- number of critical paths still lacking a minimal fix

---

## Interpretation Rules

- never let counts replace narrative risk explanation
- explain large clusters when one root cause fans out to many findings
- keep repeated pattern counts aligned with the actual finding list and explain when one finding intentionally groups multiple downstream exploit paths
- if a category is shallow or partial, reflect that in coverage notes rather than inflating counts
- keep function-chain counts aligned with coverage debt so missing chains are visible, not hidden
- keep deep-gate counts aligned with coverage debt so incomplete semantic review is visible, not hidden behind a covered category row
- keep report counts aligned with audit state ledgers; if ledger counts and report counts disagree, fix the state or report the mismatch as coverage debt
- do not count invalidated state records as reviewed, fixed, covered, or complete
- do not use historical knowledge as a substitute for current-run evidence refs
- if historical misses exist, say lifecycle counts were withheld and do not zero-fill `Fixed since last scan`
- do not mix candidate signals into confirmed severity counts
- do not mix evidence observations or schema gaps into confirmed severity counts
- do not mix supplemental-section items into confirmed finding, severity, or coverage-debt counts
