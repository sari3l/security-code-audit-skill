# Severity Controls

Use this file to keep severity assignment consistent across findings and across runs.

## Base Factors

Judge severity using:
- exploitability
- impact
- exposure
- required privileges
- scope
- data sensitivity
- chainability

## Lightweight Rubric

Score the finding before naming the level:
- exploitability: `0-2`
- impact: `0-2`
- exposure: `0-2`
- privileges required: `0-2` where lower required privilege means higher score
- scope: `0-2`
- chainability or exploit proof: `0-2`

Suggested mapping:
- `11-12` -> Critical
- `8-10` -> High
- `4-7` -> Medium
- `1-3` -> Low
- `0` -> Info

## Normalization Rules

- Similar issue class plus similar context should land at similar severity.
- Proven pre-auth compromise should usually outrank post-auth edge cases.
- Publicly reachable data access or code execution should usually outrank local or admin-only paths.
- Do not inflate severity because the issue feels familiar or scary.
- Do not deflate severity because the code path looks inconvenient if the exploit path is still credible.

## Compound-Risk Rules

- Raise severity for chains only when the chain is actually supported by evidence.
- Keep single-bug severity separate from chain severity when helpful.
- Dependency issues, debug exposure, file handling, and weak auth often compound; note that explicitly when proven.

## Calibration Guidance

- When uncertain between two levels, choose the lower one unless exploit evidence clearly supports the higher one.
- Reuse the same calibration logic across repeated findings in the same repo.
- Use `references/shared/reporting/severity-guide.md` for example mappings and report phrasing after applying these controls.
- Proven pre-auth compromise of sensitive systems should rarely land below High.
- Proven RCE, auth bypass, or broad sensitive-data compromise should usually land at Critical unless the environment facts clearly constrain impact.
