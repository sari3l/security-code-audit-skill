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
- Use `Pending historical validation` only when the finding itself is confirmed but the run's deferred history replay found at least one still-live prior vulnerability that the scan missed.
- If matching to history is ambiguous, prefer `New` over forcing a weak match.
- A prior report's `Fixed` claim must never suppress a current confirmed finding. Current code evidence wins.
- In `quick`, `standard`, and `deep`, assign historical status only after the current finding has already been built from current-code evidence and the deferred history replay found no historical misses.
- If the deferred history replay finds a still-live prior vulnerability that the current scan missed, record the miss and `Skill Optimization Suggestions` in the report before any lifecycle finalization.

## Maturity Rules

- Distinguish finding maturity from historical status.
- Use `Confirmed` for issues with enough code, exploitability, and impact evidence to enter the main findings list.
- Use `Candidate` for high-signal suspicious cases that still lack sufficient proof.
- Do not let `Candidate` entries appear in the main findings list.
- Apply `references/shared/reporting/evidence-standard.md` before promoting a suspicious case to `Confirmed`.
- Use `Working Hypotheses` for broader unresolved models such as attack chains, shared vulnerable helpers, or trust-boundary assumptions that are not yet precise enough to be written as a localized candidate finding.
- Do not use `Working Hypotheses` to smuggle half-proven findings into the main report. If the concern is a concrete code path, keep it in `Candidate Signals` until proven.
- For instruction-bearing artifacts such as `SKILL.md`, `AGENTS.md`, prompts, READMEs, and setup flows, default suspicious text to `Candidate` until the audit can show a real operator-directed execution path or trust-boundary failure.
- A confirmed skill-repo finding should identify the instruction source, the execution or trust boundary, the affected asset or control surface, and the credible operator impact.

## Negative-Evidence Rules

- When a candidate is not promoted, record the concrete reason it was not confirmed.
- Prefer explicit negative evidence over silently dropping suspicious patterns.
- Real mitigations, unreachable sinks, and environment blockers should be preserved for later review instead of being forgotten.
- Benign defensive prose, warnings, and fenced educational examples are valid negative evidence against promotion unless surrounding context turns them into a real execution path.

## Coverage-Debt Rules

- If a surface is partial, blocked, invalidated, or time-boxed, record it as coverage debt instead of pretending it was covered.
- Coverage debt is not a finding, but it is required output for honest reporting.
- Apply `references/shared/reporting/coverage-debt-standard.md` whenever a category or surface remains materially unresolved.
- If a prior finding touched the same helper, sink, or trust boundary and that path was not explicitly reopened in the current scan, record the gap as coverage debt instead of silently inheriting `Fixed`.
- A historical miss is both coverage debt and a report-quality problem; it must not be silently downgraded into a normal `Fixed` or `New` comparison outcome.

## Supplemental-Section Rules

- Use `Operational Risks`, `Integration Assumptions`, and `Engineering Notes` for reader-relevant context that should not become findings.
- Do not smuggle weak findings into these sections to avoid evidence requirements.
- Do not let these sections alter confirmed severity totals or replace real findings.
- Apply `references/shared/reporting/supplemental-sections-standard.md` when these sections are used.

## False-Report Controls

- If a suspicious pattern lacks exploitability or impact evidence, keep it out of the main findings list.
- If an instruction-bearing artifact only contains a keyword, command name, or scary-looking snippet without a credible execution path, keep it out of the main findings list.
- If remediation would be different, findings should usually stay separate.
- If multiple proof points exist for the same root cause, keep one finding and multiple locations.
- If a privileged recovery or rescue concern depends on a hypothetical future refactor, a malicious operator racing an unproven stranded-funds state, or other timing assumptions that current code evidence does not establish, keep it as `Candidate` or `Hardening`, not a confirmed main finding.
