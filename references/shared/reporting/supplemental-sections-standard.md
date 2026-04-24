# Supplemental Sections Standard

Use this standard for material report sections that improve operator readability without diluting the main vulnerability list.

These sections are not findings. They do not carry severity, CVSS, or finding IDs, and they must not be counted in confirmed severity totals.

---

## Purpose

Use supplemental sections to capture:
- operational or response risks that are real but not best framed as exploitable code vulnerabilities
- integration assumptions that materially affect safe usage, deployment, or runtime behavior
- engineering notes that are useful for maintainers but should not be inflated into findings

This keeps reports readable for mixed audiences while preserving a strict boundary around `Confirmed Findings`.

---

## Section Types

### Operational Risks

Use for material operator-facing gaps such as:
- no liquidation monitoring
- no operational runbook for a trusted dependency failure
- emergency-response friction that increases user risk during incidents
- external dependency failure modes that are real but not cleanly expressed as direct code exploitation

Do not use this section for issues that should be `Confirmed Findings`.

### Integration Assumptions

Use for material preconditions or trust assumptions such as:
- users must pre-configure delegation, approvals, or protocol settings
- off-chain scripts must provide non-zero slippage bounds
- deployment or upgrade steps must happen in a strict order
- whitelists, routers, relayers, or operators are assumed to exist and stay functional

If violating the assumption itself creates a concrete exploitable bug in the present code path, write a finding instead.

### Engineering Notes

Use for lower-stakes but still useful notes such as:
- test coverage blind spots
- dead code or dead interfaces
- observability gaps with limited direct security impact
- consistency improvements that help maintenance but do not justify a finding

Do not use this section for praise, release notes, or generic best-practice filler.

---

## Inclusion Rules

- Include these sections only when they add signal for a real reader.
- Prefer omission over padding.
- Do not let supplemental sections overshadow confirmed findings, candidate signals, or coverage debt.
- Do not use supplemental sections to down-rank a real finding.
- Do not promote wishlist features into supplemental sections unless they materially affect safe operation.

---

## Writing Rules

- Keep each item concise and decision-oriented.
- Explain why the note matters in practice, not just in theory.
- Use file references when the issue is anchored in code.
- Use operational language for operational risks, not exploit language.
- Make integration assumptions explicit about who owns the requirement: user, operator, deployer, relayer, or script.
- Keep engineering notes action-oriented and low-drama.

---

## Minimal Shapes

```markdown
## Operational Risks

### OPR-001: [Title]
- **Why It Matters**: [Practical operational consequence]
- **Where It Shows Up**: `file/path.ext:line` or [runtime/dependency path]
- **Recommendation**: [Smallest useful operational or product response]
```

```markdown
## Integration Assumptions

### ASM-001: [Title]
- **Assumption**: [What must already be true]
- **Where It Matters**: `file/path.ext:line` or [runtime/dependency path]
- **Failure Mode**: [What happens when the assumption is false]
- **Recommendation**: [Validation, documentation, preflight, or guard]
```

```markdown
## Engineering Notes

### ENG-001: [Title]
- **Observation**: [Concise technical note]
- **Where It Shows Up**: `file/path.ext:line`
- **Recommendation**: [Useful cleanup or test/observability improvement]
```

---

## Reporting Rules

- These sections are optional.
- Place them after `Coverage Debt` and before `Attack Chains` when present.
- Do not include them in the severity table.
- Do not assign CVSS.
- Do not mix them into `Confirmed Findings`, `Candidate Signals`, or `Coverage Debt` counts.
