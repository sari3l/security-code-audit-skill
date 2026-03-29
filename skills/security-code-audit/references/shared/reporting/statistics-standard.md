# Statistics Standard

Statistics should support triage and coverage, not just make the report look complete.

---

## Required Counts

- confirmed findings by severity using underlying fingerprint-backed issue counts
- findings by category or domain surface
- findings by status: new, recurring, regression, fixed since last scan
- candidate signal count
- coverage debt item count
- applicable categories or domain surfaces covered vs not applicable
- number of API versions reviewed
- number of template/view files reviewed
- number of config and deployment files reviewed when present

---

## Useful Optional Metrics

- presented finding count when exploit-first splits multiple operator-significant findings out of one shared root cause
- grouped root-cause count when governance intentionally merges multiple downstream exploit paths under one remediation boundary
- number of endpoints audited
- number of affected endpoints for repeated patterns
- number of attack chains identified
- number of open working hypotheses in Deep or beta `multi` reports
- number of operational risks, integration assumptions, or engineering notes when these sections are present
- number of secrets or credentials exposed
- number of critical paths still lacking a minimal fix

---

## Interpretation Rules

- never let counts replace narrative risk explanation
- explain large clusters when one root cause fans out to many findings
- keep repeated pattern counts aligned with the actual finding list and explain whether the report is showing root-cause grouping or exploit-path presentation
- do not let exploit-first presentation splits double-count one underlying issue in historical or regression comparisons
- if a category is shallow or partial, reflect that in coverage notes rather than inflating counts
- do not mix candidate signals into confirmed severity counts
- do not mix supplemental-section items into confirmed finding, severity, or coverage-debt counts
