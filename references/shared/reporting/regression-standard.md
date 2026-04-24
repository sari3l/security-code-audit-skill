# Regression Retest Standard

Use this standard when mode is `regression`.

## Purpose

Regression mode is for remediation verification, not broad vulnerability discovery.

It answers:
- which findings from the latest report are fixed
- which findings are still present
- which findings are only partially fixed
- which findings could not be retested reliably
- how the current deployment or integration context changed the real attack preconditions for those findings when that context is material

## Baseline Selection

- read the most recent usable standardized report from `.security-code-audit-reports/`, choosing by parsed filename timestamp first
- use that report as the only required retest baseline
- do not merge multiple older reports into one retest target set unless the user explicitly asks

Preferred recency order:
- parse the leading filename timestamp in the format `YYYY-MM-DD-HHMMSS`
- only treat files matching the current standard filename shape `{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}.md` as usable regression baselines
- ignore older alternate filename shapes instead of trying to normalize them into the new flow
- if multiple reports share the same timestamp, prefer the newest file mtime
- treat placeholder times as invalid if they were not generated from the real wall-clock time for that report
- if filename timestamp and report `Date` metadata disagree materially, prefer the value backed by the real captured timestamp or file mtime
- if parsing fails or the name is non-standard, ignore that file as a regression baseline
- if metadata is missing or malformed on an otherwise-standard file, fall back to file mtime

If no usable baseline report exists:
- print a concise note
- stop the run
- do not perform a fallback broad scan

## Retest Target Selection

Extract from the latest report:
- finding id or title
- category
- fingerprint
- affected routes, resources, or sinks
- prior attack vector
- prior minimal fix expectation
- prior deployment, exposure, auth-owner, or network assumptions when they were stated or can be inferred from the prior attack vector

If the latest report has no usable findings, stop with a concise note.

## Retest Statuses

- `Fixed`
  The prior exploit path is no longer credible and the vulnerable control is materially repaired.

- `Still Present`
  The prior exploit path still works or the same control gap remains.

- `Partially Fixed`
  Some locations or paths were repaired, but the vulnerability remains materially exploitable somewhere in scope.

- `Unable To Verify`
  Reliable retest is blocked by missing code, missing environment, or insufficient evidence.

## Retest Rules

- use the prior fingerprint first, then route/resource family, then prior exploit path
- validate the current code directly; do not trust the prior report as proof
- reopen the current deployment or integration path when exploitability depends on a host app, reverse proxy, mount prefix, service mesh, or internal-only network placement
- if a finding moved but the exploit path is still materially the same, keep it tied to the same baseline finding
- if the fix changed the code shape but left equivalent exposure, classify as `Still Present` or `Partially Fixed`, not `Fixed`
- do not classify a finding as `Fixed` solely because an external control reduced exposure; if the code weakness remains, keep the retest status grounded in the current code and record the lower real-world attack preconditions separately
- when deployment or integration context materially lowers actual risk without removing the underlying weakness, explain both the reduced exposure and the remaining residual risk
- do not create a new broad finding list for unrelated surfaces during regression mode

## Output Requirements

Terminal summary should include:
- baseline report used
- count of `Fixed`
- count of `Still Present`
- count of `Partially Fixed`
- count of `Unable To Verify`
- concise context-drift notes when deployment or integration changes materially altered exposure for one or more retested findings

History file should include:
- baseline report metadata
- baseline report timestamp
- one retest entry per prior finding
- concise rationale for each retest status
- explicit blockers where retest confidence is limited
- current exposure or integration context when it materially changes the real attack preconditions

## Minimal Retest Entry Shape

```markdown
### [RETEST]-[NNN]: [Prior Finding Title]
- **Baseline Report**: [file]
- **Baseline Timestamp**: [YYYY-MM-DD HH:MM:SS TZ]
- **Fingerprint**: [stable finding fingerprint]
- **Prior Severity**: Critical / High / Medium / Low / Info
- **Retest Status**: Fixed / Still Present / Partially Fixed / Unable To Verify
- **Current Location**: `file/path.ext:line` or `N/A`
- **Current Exposure Context**: [public, internal-only, host-app-auth, reverse-proxy-restricted, or similar when material]
- **Retest Notes**: [What changed and what still holds]
- **Context Drift**: [How deployment or integration changed the actual risk or attack preconditions, if material]
- **Evidence**:
  ```[lang]
  // Current relevant code or config
  ```
- **Residual Risk**: [Only if still present or partially fixed]
```
