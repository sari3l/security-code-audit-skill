# Coverage Debt Standard

Use this standard to record important surfaces that were only partially reviewed, blocked, or invalidated during the current audit.

---

## Purpose

Coverage debt exists so the report stays honest about what was not fully verified.

This helps prevent false confidence when:
- the repo is too large for one pass
- a surface changed late in the scan
- runtime context or environment is missing
- dynamic behavior blocked deeper verification
- the audit chose depth in one area at the expense of another

Coverage debt is not itself a vulnerability finding.

---

## When To Record Coverage Debt

Create a coverage-debt item when a surface is:
- `Partial`
- `Blocked`
- `Invalidated`
- `Time-boxed`

Typical examples:
- auth middleware reviewed on core routes but not all legacy routes
- dynamic template rendering inferred but not fully traced
- runtime-only config or feature flag unavailable
- dependency tooling blocked by missing command or offline environment
- contract invariant suspected but not fully reconstructed

---

## Required Fields

- `Surface`
- `State`
- `Reason`
- `Risk If Wrong`
- `Re-Audit Trigger`
- `Suggested Next Step`

---

## Minimal Entry Shape

```markdown
### [DEBT]-[NNN]: [Surface]
- **State**: Partial / Blocked / Invalidated / Time-boxed
- **Reason**: [Why this surface was not fully verified]
- **Risk If Wrong**: [What may still be hidden here]
- **Re-Audit Trigger**: [What change or condition should force review]
- **Suggested Next Step**: [What the next audit should do]
```

---

## Reporting Rules

- Include coverage debt in the final report whenever the audit is not truly exhaustive.
- Treat high-risk unresolved control surfaces as more important than low-severity cosmetic findings.
- If a category or domain surface is marked partial in coverage, create at least one coverage-debt note explaining why.
