# Regression Mode

Targeted remediation retest mode.

---

## Scope

Retest the most recent vulnerability report instead of performing a new broad audit.

Use when:
- you want to verify whether previously reported issues were actually fixed
- a release gate needs focused remediation validation
- the latest `.security-code-audit-reports/` report should be treated as the retest baseline

If no usable recent report exists, stop immediately with a concise note instead of running a fresh scan.

---

## Required Load

- `references/shared/reporting/index.md`
- `references/shared/reporting/history-standard.md`
- `references/shared/reporting/regression-standard.md`
- only the language, framework, vulnerability, exploit, and dependency modules needed for the prior findings being retested

Use the matching exploit index only when a prior finding must be re-verified with a concrete exploit path:
- `references/application/exploits/index.md` for application findings
- `references/smart-contract/exploits/index.md` for contract findings

---

## Recon Depth

Required:
- load the latest usable `.security-code-audit-reports/` report
- extract the prior finding set and their fingerprints
- map only the files, routes, helpers, configs, and trust boundaries needed to retest those findings

Not required:
- full route inventory
- full C1-C12 coverage
- full business-logic sweep
- new broad attack-surface discovery

---

## Progress Labels

Regression mode uses the shared 6-step progress display from `SKILL.md`, but the middle stages should be labeled exactly as:

- `[3/6] Load latest report and map prior findings`
  Build the retest target set from the most recent report and identify the affected surfaces.
- `[4/6] Retest prior findings against current code`
  Verify whether each prior finding is fixed, still present, or blocked from reliable retest.
- `[5/6] Classify remediation results and baseline drift`
  Normalize retest outcomes, history notes, and any scope drift from the prior report.

---

## Scan Tasks

- read the chosen baseline report only
- retest each prior finding using its fingerprint, route/resource family, and exploit path
- verify whether the prior fix actually breaks exploitation
- record `Fixed`, `Still Present`, `Partially Fixed`, or `Unable To Verify`
- note if a finding moved, widened, or changed shape while remaining materially unfixed

Do not turn regression mode into a broad new audit.

If an obvious unrelated Critical or High issue appears during retest:
- note it as out-of-scope signal
- do not expand into a full scan unless the user asks

---

## Output

- terminal summary
- regression retest history file in `.security-code-audit-reports/`
- fixed / still-present / blocked counts based on the latest baseline report

---

## Termination Criteria

Regression mode is complete when:
- the latest usable report was found, or an early-exit reason was recorded
- every retest target from that report was classified
- blockers or ambiguous cases were recorded explicitly
- the retest summary was generated
