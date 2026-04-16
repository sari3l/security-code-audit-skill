# Reporting Standards

This directory contains reusable standards for Phase 4 report generation.

Operational quality controls such as false-positive prevention, coverage discipline, finding consistency, and severity normalization now live in `core/`.

Use these files to keep reports consistent, auditable, and actionable:
- `coverage-matrix.md` for post-scan coverage verification before reporting
- `coverage-debt-standard.md` for partial, blocked, invalidated, time-boxed, or missing-function-chain coverage gaps
- `evidence-standard.md` for candidate vs confirmed findings and negative evidence handling
- `finding-detail-standard.md` for each individual finding entry
- `history-standard.md` for comparing current findings against previous timestamped reports
- `hypothesis-standard.md` for deep or multi-agent working hypotheses that remain unresolved but material
- `regression-standard.md` for retesting the most recent timestamped report instead of running a broad new audit
- `severity-guide.md` for severity calibration and context-sensitive grading
- `supplemental-sections-standard.md` for operational risks, integration assumptions, and engineering notes that should stay outside the main findings list
- `poc-standard.md` for exploit evidence and reproduction quality
- `remediation-standard.md` for minimal real fixes and hardening guidance
- `overview-standard.md` for executive summary, top findings, and action items
- `statistics-standard.md` for counts, coverage, and trend reporting
- `VERSIONING.md` for the skill version carried into report metadata
- `references/smart-contract/vulnerabilities/coverage.md` when the active domain is `smart-contract`

---

## Loading Guidance

- Load `coverage-matrix.md` before writing the final report.
- Load `coverage-debt-standard.md` whenever a category, surface, or in-scope function chain is partial, blocked, invalidated, time-boxed, or missing.
- Load `evidence-standard.md` before promoting suspicious patterns into the main findings list.
- For artifact-centric audits of skill, agent, or instruction-bearing repos, load the existing artifact review path and reconcile operator-risk coverage before finalizing the report.
- Load `hypothesis-standard.md` in `deep` mode or beta `multi` execution whenever unresolved high-signal hypotheses remain material after final verification.
- Load `supplemental-sections-standard.md` when the audit has reader-relevant operational risks, integration assumptions, or engineering notes that should not be inflated into confirmed findings.
- If the active knowledge domain is `smart-contract`, load `references/smart-contract/vulnerabilities/coverage.md` instead of relying only on the generic application coverage matrix.
- Load `finding-detail-standard.md` and `remediation-standard.md` for every Standard or Deep audit report.
- Load `history-standard.md` after the independent current-code scan is complete when reading `.security-code-audit-reports/` history files, ordering them by report timestamp, and writing `Historical Context`.
- Load `regression-standard.md` when mode is `regression` and the latest timestamped report becomes the retest baseline.
- Apply `core/fingerprints.md` before `history-standard.md` when matching current findings to prior reports.
- Load `poc-standard.md` whenever a finding is Critical, High, or otherwise needs reproduction evidence.
- Apply `core/severity.md` first when assigning severity, then use `severity-guide.md` for example mappings and report phrasing.
- Load `overview-standard.md` and `statistics-standard.md` when generating the final report summary.
- Reconcile counted coverage totals and function-chain totals against audit state before finalizing the report.
- Load `VERSIONING.md` when writing report metadata so the output records the skill revision used.
- Keep the report concise, but never drop exploitability, evidence, minimal-fix guidance, candidate signals, coverage debt, or historical context.
