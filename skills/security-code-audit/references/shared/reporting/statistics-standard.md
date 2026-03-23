# Statistics Standard

Statistics should support triage and coverage, not just make the report look complete.

---

## Required Counts

- confirmed findings by severity
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

- number of endpoints audited
- number of affected endpoints for repeated patterns
- number of attack chains identified
- number of open working hypotheses in Deep or beta `multi` reports
- number of secrets or credentials exposed
- number of critical paths still lacking a minimal fix

---

## Interpretation Rules

- never let counts replace narrative risk explanation
- explain large clusters when one root cause fans out to many findings
- keep repeated pattern counts aligned with the actual finding list
- if a category is shallow or partial, reflect that in coverage notes rather than inflating counts
- do not mix candidate signals into confirmed severity counts
