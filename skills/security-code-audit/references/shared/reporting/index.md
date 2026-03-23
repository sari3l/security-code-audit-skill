# Reporting Standards

This directory contains reusable standards for Phase 4 report generation.

Operational quality controls such as false-positive prevention, coverage discipline, finding consistency, and severity normalization now live in `core/`.

Use these files to keep reports consistent, auditable, and actionable:
- `coverage-matrix.md` for post-scan coverage verification before reporting
- `coverage-debt-standard.md` for partial, blocked, invalidated, or time-boxed surfaces
- `evidence-standard.md` for candidate vs confirmed findings and negative evidence handling
- `finding-detail-standard.md` for each individual finding entry
- `history-standard.md` for comparing current findings against previous timestamped reports
- `hypothesis-standard.md` for deep or multi-agent working hypotheses that remain unresolved but material
- `regression-standard.md` for retesting the most recent timestamped report instead of running a broad new audit
- `severity-guide.md` for severity calibration and context-sensitive grading
- `poc-standard.md` for exploit evidence and reproduction quality
- `remediation-standard.md` for minimal real fixes and hardening guidance
- `overview-standard.md` for executive summary, top findings, and action items
- `statistics-standard.md` for counts, coverage, and trend reporting
- `VERSIONING.md` for the skill version carried into report metadata
- `references/smart-contract/vulnerabilities/coverage.md` when the active domain is `smart-contract`

---

## Loading Guidance

- Load `coverage-matrix.md` before writing the final report.
- Load `coverage-debt-standard.md` whenever a category or surface is partial, blocked, invalidated, or time-boxed.
- Load `evidence-standard.md` before promoting suspicious patterns into the main findings list.
- Load `hypothesis-standard.md` in `deep` mode or beta `multi` execution whenever unresolved high-signal hypotheses remain material after final verification.
- If the active knowledge domain is `smart-contract`, load `references/smart-contract/vulnerabilities/coverage.md` instead of relying only on the generic application coverage matrix.
- Load `finding-detail-standard.md` and `remediation-standard.md` for every Standard or Deep audit report.
- Load `history-standard.md` when reading `.security-code-audit-reports/` history files, ordering them by report timestamp, and writing `Historical Context`.
- Load `regression-standard.md` when mode is `regression` and the latest timestamped report becomes the retest baseline.
- Apply `core/fingerprints.md` before `history-standard.md` when matching current findings to prior reports.
- Load `poc-standard.md` whenever a finding is Critical, High, or otherwise needs reproduction evidence.
- Apply `core/severity.md` first when assigning severity, then use `severity-guide.md` for example mappings and report phrasing.
- Load `overview-standard.md` and `statistics-standard.md` when generating the final report summary.
- Load `VERSIONING.md` when writing report metadata so the output records the skill revision used.
- Keep the report concise, but never drop exploitability, evidence, or minimal-fix guidance.
