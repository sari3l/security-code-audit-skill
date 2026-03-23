# Finding Controls

Use this file to keep finding boundaries, grouping, dedupe, and lifecycle handling consistent.

## Granularity Rules

- Each distinct vulnerability type should be its own finding.
- Same vulnerability across multiple endpoints may be grouped only if all affected locations are listed explicitly.
- Different vulnerability types in the same function or route are separate findings.
- Do not merge unrelated endpoints into one finding just because the sink type is the same.

## Dedupe Rules

- Deduplicate only when exploit path, root cause, and fix are materially the same.
- Do not deduplicate across different owners, resources, or route families if remediation would differ.
- Do not double count the same dependency advisory from native audit and external SCA results.
- Apply `core/fingerprints.md` before merging history matches, worker output, or repeated locations.

## Fingerprint Rules

- Every finding should carry one stable fingerprint before status assignment.
- Fingerprints should survive moved lines, refactors, and renamed files when the exploit path is still the same.
- If two candidates need different fixes, they usually need different fingerprints.

## Status Rules

- Use `New`, `Recurring`, `Regression`, and `Fixed` consistently with `references/shared/reporting/history-standard.md`.
- If matching to history is ambiguous, prefer `New` over forcing a weak match.

## Maturity Rules

- Distinguish finding maturity from historical status.
- Use `Confirmed` for issues with enough code, exploitability, and impact evidence to enter the main findings list.
- Use `Candidate` for high-signal suspicious cases that still lack sufficient proof.
- Do not let `Candidate` entries appear in the main findings list.
- Apply `references/shared/reporting/evidence-standard.md` before promoting a suspicious case to `Confirmed`.
- Use `Working Hypotheses` for broader unresolved models such as attack chains, shared vulnerable helpers, or trust-boundary assumptions that are not yet precise enough to be written as a localized candidate finding.
- Do not use `Working Hypotheses` to smuggle half-proven findings into the main report. If the concern is a concrete code path, keep it in `Candidate Signals` until proven.

## Negative-Evidence Rules

- When a candidate is not promoted, record the concrete reason it was not confirmed.
- Prefer explicit negative evidence over silently dropping suspicious patterns.
- Real mitigations, unreachable sinks, and environment blockers should be preserved for later review instead of being forgotten.

## Coverage-Debt Rules

- If a surface is partial, blocked, invalidated, or time-boxed, record it as coverage debt instead of pretending it was covered.
- Coverage debt is not a finding, but it is required output for honest reporting.
- Apply `references/shared/reporting/coverage-debt-standard.md` whenever a category or surface remains materially unresolved.

## False-Report Controls

- If a suspicious pattern lacks exploitability or impact evidence, keep it out of the main findings list.
- If remediation would be different, findings should usually stay separate.
- If multiple proof points exist for the same root cause, keep one finding and multiple locations.
