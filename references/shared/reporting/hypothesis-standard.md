# Working Hypothesis Standard

Use this standard for material unresolved hypotheses that should remain visible in deep or beta multi-agent audits without being overstated as confirmed findings.

---

## Purpose

`Working Hypotheses` are for broader models such as:
- suspected attack chains that still need one or more proof steps
- shared vulnerable helpers or shared trust assumptions
- combinations of individually small weaknesses that may become serious when chained
- control-boundary explanations that may connect multiple candidates
- high-signal theories that could materially change risk if validated

They are not a substitute for `Candidate Signals`.

Use:
- `Candidate Signals` for localized suspected vulnerabilities in specific code paths
- `Working Hypotheses` for broader attack, trust, or root-cause models still under validation

---

## When To Include

Include a `Working Hypotheses` appendix only when:
- mode is `deep`, or
- execution is beta `multi`

Then include it only if unresolved hypotheses remain material after final verification.

Do not add this appendix to keep the report looking busy.

---

## Export Rules

Internal state may track:
- `open`
- `validated`
- `rejected`
- `deprioritized`

Final report appendix should normally include only:
- `Open`
- `Deprioritized`

Do not leave `Validated` items in the appendix:
- promote them into `Confirmed Findings`, `Attack Chains`, or both

Do not include `Rejected` items in the final report:
- keep them in audit state only

---

## Required Fields

- `Type`
- `Status`
- `Related Surfaces`
- `Related Findings / Chain Inputs` when material
- `Why It Matters`
- `Evidence For`
- `Evidence Against / Friction`
- `Next Validation Step`
- `Owner` when execution is `multi`

---

## Writing Rules

- Keep hypotheses concrete enough that another reviewer can continue validation.
- Tie each hypothesis to actual surfaces, files, or trust boundaries already observed.
- Make the missing proof step explicit.
- Prefer one hypothesis per attack or control model; do not merge unrelated theories.
- Do not restate confirmed findings here.
- If the hypothesis becomes a concrete code-level suspicion, move it into `Candidate Signals`.

---

## Minimal Entry Shape

```markdown
## Working Hypotheses (deep or multi when material)

### [HYP]-[NNN]: [Title]
- **Type**: Attack Chain / Shared Helper / Trust Boundary / Compound Risk / Proof Challenge
- **Status**: Open / Deprioritized
- **Related Surfaces**: [routes, modules, contracts, trust boundaries]
- **Related Findings / Chain Inputs**: [findings or candidate signals that compose]
- **Why It Matters**: [What risk changes if this is true]
- **Evidence For**: [Observed facts that support the hypothesis]
- **Evidence Against / Friction**: [Observed facts that weaken it or blockers that remain]
- **Next Validation Step**: [What should confirm or reject it next]
- **Owner**: Supervisor / Surface-Auditor / Validator / Shared-Surface-Auditor / Dependency-Auditor (multi only)
```
