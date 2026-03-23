# Artifact-Centric Profile

Use this profile when the repo is dominated by markdown, prompts, skill files, API specs, notebooks, or other instruction-bearing and rendered assets rather than runtime application code.

The visible progress should reflect instruction boundaries, rendering trust, secrets in artifacts, drift, and operator-facing abuse paths.

---

## Progress Labels

### Quick

- `[3/6] Triage instruction, rendering, and trust surfaces`
- `[4/6] Check secrets, dependency, and environment red flags`
- `[5/6] Minimal verification, drift analysis, and report prep`

### Standard

- `[3/6] Audit instruction, rendering, and trust surfaces`
- `[4/6] Audit data exposure, dependency, and environment surfaces`
- `[5/6] Coverage, drift, and history`

### Deep

- `[3/6] Deep instruction, rendering, and trust analysis`
- `[4/6] Exhaustive data, dependency, and environment review`
- `[5/6] Abuse chains, drift analysis, strict coverage, and history`

---

## Emphasis Notes

- prompt injection, instruction precedence, and rendered-content trust should appear early
- secrets, environments, examples, saved outputs, and operational leakage should dominate later stages
- post-category analysis should use drift and abuse-chain language rather than web-app business-flow wording

---

## Audit Routing

- use `references/application/index.md` as the primary knowledge domain router
- prioritize `references/shared/artifacts/index.md` and the matching artifact modules early
- treat generic application vulnerability modules as supporting lenses where they help explain artifact-driven risk
