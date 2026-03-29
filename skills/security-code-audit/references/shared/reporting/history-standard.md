# History Comparison Standard

Use this standard when reading previous reports from `.security-code-audit-reports/` and deciding whether a current finding is `New`, `Recurring`, `Regression`, or `Fixed`.

---

## Purpose

History comparison exists to answer:
- what is newly introduced
- what still exists
- what was fixed
- what reappeared after previously disappearing

The goal is trend clarity, not forced matching. Prefer conservative comparison over inventing continuity where the evidence is weak.

---

## Inputs

Use:
- the current draft finding list
- up to 3 most recent standardized report timestamp families from `.security-code-audit-reports/`, ordered by parsed filename timestamp first
- the current code locations and exploit paths
- stable finding fingerprints from `core/fingerprints.md`

If there is no usable history, state that clearly and mark current findings as `New`.

Preferred recency order:
- parse the leading filename timestamp family in the format `YYYY-MM-DD-HHMMSS`
- if multiple reports share the same timestamp family, prefer:
  1. `governance`
  2. `exploit-first`
  3. legacy no-style reports
- treat example values as invalid if they were not generated from the real wall-clock time for that report
- if filename timestamp and report `Date` metadata disagree materially, treat that report as suspicious and prefer the value backed by the real captured timestamp or file mtime
- if parsing fails or the name is non-standard, fall back to the report `Date` metadata
- if metadata is missing or malformed, fall back to file mtime

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

---

## Comparison Process

1. Read up to 3 latest report timestamp families from `.security-code-audit-reports/`, ordered by parsed filename timestamp first and preferring governance within the same family.
2. Extract prior findings with category, fingerprint, title, location, attack vector, impact, and related notes.
3. Normalize paths mentally for refactors: line movement alone does not make a finding new.
4. Match current findings against the most recent report first, using fingerprint before prose title matching.
5. Use older reports only to identify regressions or longer-term persistence.
6. Build a separate `Fixed` list from prior findings that no longer have a credible current match.

---

## Output Requirements

For each current finding:
- assign `New`, `Recurring`, or `Regression`
- carry the fingerprint used for comparison

For the report summary:
- count `New`
- count `Recurring`
- count `Regression`
- count `Fixed since last scan`

For `Historical Context`, explain:
- what changed since the most recent prior scan
- whether repeated issues cluster around the same root cause
- whether regressions suggest control drift, version drift, or incomplete remediation
- when the prior timestamp family contained both report styles, treat governance as the preferred internal reference and use exploit-first only as fallback

---

## Good Comparison Notes

Examples of useful notes:
- "Recurring: same raw SQL helper still used, line numbers changed after refactor."
- "Regression: admin route authz gap existed two scans ago, was absent in the last scan, now present in `/v1/admin/users` again."
- "Fixed since last scan: prior debug endpoint exposure no longer reachable and config path removed."

---

## Avoid

- matching only on title text
- treating line-number drift as a new finding by default
- collapsing multiple current endpoints into one old finding without explicit justification
- calling a finding fixed when the vulnerable pattern simply moved to another module
