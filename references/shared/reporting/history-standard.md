# History Comparison Standard

Use this standard when reading previous reports from `.security-code-audit-reports/` and deciding whether historical lifecycle can be finalized as `New`, `Recurring`, `Regression`, or `Fixed`, or must stay `Pending historical validation`.

---

## Purpose

History comparison exists to answer:
- what is newly introduced
- what still exists
- what was fixed
- what reappeared after previously disappearing

The goal is trend clarity after an independent current-code audit, not forced matching. Prefer conservative comparison over inventing continuity where the evidence is weak.

---

## Inputs

Use:
- the current draft finding list
- the current coverage state and function-chain records
- up to 3 most recent standardized reports from `.security-code-audit-reports/`, ordered by parsed filename timestamp first
- the current code locations and exploit paths
- stable finding fingerprints from `core/fingerprints.md`

For `quick`, `standard`, and `deep`:
- do not read prior report details until the current draft findings, coverage reconciliation, and audit state are complete
- build the current draft findings from current-code evidence before history matching
- treat prior `Fixed` claims as low-trust hints until the current code path is reopened
- treat prior reports as post-scan comparison input only
- do not let history narrow scan scope, guide search order, or suppress a current finding
- never describe history review as pre-scan "background" for the current audit; it begins only after the independent current-code pass is already stable

If there is no usable history, state that clearly and mark current findings as `New`.

Preferred recency order:
- parse the leading filename timestamp in the format `YYYY-MM-DD-HHMMSS`
- only treat files matching the current standard filename shape `{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}.md` as usable history input
- ignore older alternate filename shapes instead of trying to normalize them into the new flow
- if multiple reports share the same timestamp, prefer the newest file mtime
- treat example values as invalid if they were not generated from the real wall-clock time for that report
- if filename timestamp and report `Date` metadata disagree materially, treat that report as suspicious and prefer the value backed by the real captured timestamp or file mtime
- if parsing fails or the name is non-standard, ignore that file for standard history comparison
- if metadata is missing or malformed on an otherwise-standard file, fall back to file mtime

---

## Status Definitions

- `New`
  No credible prior match exists in the recent report set.

- `Recurring`
  A substantially similar finding exists in the most recent prior report and is still present.

- `Regression`
  A substantially similar finding existed in an older report, disappeared from a newer report, and is now present again.

- `Fixed`
  A prior finding from the most recent report no longer has a credible current match.

`Fixed` is usually reported in historical summary sections, not as a status on a current finding entry.

In `quick`, `standard`, and `deep`, `Fixed` is a history-summary conclusion only. It is never a reason to skip re-reading the current helper, sink, route family, or trust boundary.

- `Pending historical validation`
  The current finding is confirmed, but the run-wide post-scan history replay found at least one still-live prior vulnerability that this audit missed, so lifecycle labels are withheld until the miss is addressed.

---

## Matching Rules

Match findings using substance, not title text alone.

Strong matching signals:
- same fingerprint
- same vulnerability family
- same endpoint, route, handler, sink, or trust boundary
- same affected resource pattern such as IDOR on the same object family
- same exploit path even if exact line numbers moved
- same framework helper or shared vulnerable utility reused after refactor

Weak signals that should not be used alone:
- same severity
- same generic title such as "SQL Injection"
- same file name without the same sink or path

Do not merge different endpoints or different vulnerability families into one historical match just because they are similar.

---

## Recommended Matching Order

1. exact same vulnerability family and same endpoint or sink
2. same vulnerability family and same shared helper or trust boundary, with moved lines or refactored files
3. same vulnerability family and same exploit path after route or module renaming

If confidence is low, prefer `New` plus a note rather than a forced `Recurring` or `Regression`.
If the latest report says a finding was fixed but the current code still shows the same exploit path, classify it as `Recurring` based on current code.

---

## Comparison Process

1. Finish the current-code scan, coverage reconciliation, and audit-state writes first.
2. Build the current draft findings from current-code evidence first.
3. Read up to 3 latest standardized reports from `.security-code-audit-reports/`, ordered by parsed filename timestamp first.
4. Extract prior findings with category, fingerprint, title, location, attack vector, impact, and related notes.
5. Normalize paths mentally for refactors: line movement alone does not make a finding new.
6. Reopen prior findings against current code before lifecycle matching to detect `Historical Misses`.
7. A `Historical Miss` exists when a prior finding's vulnerable exploit path, helper, sink, route family, or trust boundary still exists in current code but the current scan produced no matching current finding.
8. When a prior finding explicitly cited multiple current-code locations or sibling helpers for the same invariant, reopen each cited helper or location before declaring the finding fixed. Rechecking only one side of the invariant is not sufficient.
9. If a prior finding was remediated only on one helper but the same failed control still exists in a sibling helper, treat that as a `Historical Miss` or a still-live current finding, not `Fixed`.
10. If any historical miss exists:
   - record each miss with current code anchors
   - emit `Skill Optimization Suggestions` explaining which routing, checklist, search pattern, state field, or coverage rule should be tightened
   - mark historical comparison as incomplete
   - use `Pending historical validation` if a status field must still be emitted on current findings
   - stop before producing `New`, `Recurring`, `Regression`, or `Fixed since last scan`
11. Only when no historical misses remain, match current findings against the most recent report first, using fingerprint before prose title matching.
12. Use older reports only to identify regressions or longer-term persistence.
13. Build a separate `Fixed` list from prior findings that no longer have a credible current match after reopening the current code path they previously touched.

---

## Output Requirements

For each current finding:
- if the historical-miss gate passed, assign `New`, `Recurring`, or `Regression`
- if the historical-miss gate failed, use `Pending historical validation`
- carry the fingerprint used for comparison

For the report summary:
- if the historical-miss gate passed, count `New`, `Recurring`, `Regression`, and `Fixed since last scan`
- if the historical-miss gate failed, count `Historical Misses`, explain that lifecycle comparison is withheld, and do not report `Fixed since last scan`
- emit `Skill Optimization Suggestions` whenever `Historical Misses` are non-zero

For `Historical Context`, explain:
- if historical misses exist, which prior vulnerabilities still exist in current code and why the current scan missed them
- what scan-routing, checklist, search-pattern, or state-tracking changes would reduce the false-negative risk next time
- otherwise, what changed since the most recent prior scan
- whether repeated issues cluster around the same root cause
- whether regressions suggest control drift, version drift, or incomplete remediation

---

## Good Comparison Notes

Examples of useful notes:
- "Recurring: same raw SQL helper still used, line numbers changed after refactor."
- "Regression: admin route authz gap existed two scans ago, was absent in the last scan, now present in `/v1/admin/users` again."
- "Fixed since last scan: prior debug endpoint exposure no longer reachable and config path removed."
- "Historical miss: prior report already covered the helper-level sweep path, current code still exposes it, and this run failed to rediscover it; tighten the helper recheck and function-chain checkpoints for that trust boundary."
- "Historical miss: prior finding cited both `_assertNoConflictingPosition` and `_getManagedPositionETH`; only the first helper was rechecked, so the sibling helper drift was wrongly closed as fixed."

---

## Avoid

- matching only on title text
- treating line-number drift as a new finding by default
- collapsing multiple current endpoints into one old finding without explicit justification
- calling a finding fixed when the vulnerable pattern simply moved to another module
- using a prior regression or remediation report as proof that the same current code path is now safe
- finalizing lifecycle labels before checking for historical misses
