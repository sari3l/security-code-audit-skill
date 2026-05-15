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
- missing bounded function-chain output for a security-relevant function still in scope
- missing required deep semantic gate output for a high-risk `deep` surface
- carrying unresolved proof obligations that affect coverage, exploitability, remediation, or severity
- carrying material audit state inventory/index limitations or unrouted `evidence-observations.jsonl` records that affect security-relevant coverage
- failing an audit state quality gate such as missing `current-change-context.json`, unresolved final-blocking merge queue item, invalidated record used as coverage, or unreconciled function-chain counts

Typical examples:
- auth middleware reviewed on core routes but not all legacy routes
- dynamic template rendering inferred but not fully traced
- runtime-only config or feature flag unavailable
- dependency tooling blocked by missing command or offline environment
- contract invariant suspected but not fully reconstructed
- SSRF final destination behavior depends on runtime DNS/proxy behavior that could not be verified
- file lifecycle traced through upload but not through presign, CDN, or download authorization
- oracle dependency semantics or rounding behavior could not be reconciled across all consumers

---

## Required Fields

- `Surface`
- `State`
- `Reason`
- `Affected Functions / Chains`
- `Related Deep Gates / Proof Obligations`
- `Related Evidence Observations / Code Fact Limitations`
- `Risk If Wrong`
- `Re-Audit Trigger`
- `Suggested Next Step`

---

## Minimal Entry Shape

```markdown
### [DEBT]-[NNN]: [Surface]
- **State**: Partial / Blocked / Invalidated / Time-boxed
- **Reason**: [Why this surface was not fully verified]
- **Affected Functions / Chains**: [functions, helpers, or transitions still lacking bounded chain output]
- **Related Deep Gates / Proof Obligations**: [gate ids or proof obligation ids when applicable]
- **Related Evidence Observations / Code Fact Limitations**: [observation ids or limitation ids when applicable]
- **Risk If Wrong**: [What may still be hidden here]
- **Re-Audit Trigger**: [What change or condition should force review]
- **Suggested Next Step**: [What the next audit should do]
```

---

## Reporting Rules

- Include coverage debt in the final report whenever the audit is not truly exhaustive.
- Treat high-risk unresolved control surfaces as more important than low-severity cosmetic findings.
- If a category or domain surface is marked partial in coverage, create at least one coverage-debt note explaining why.
- If an in-scope security-relevant function lacks a bounded call-chain record, create at least one coverage-debt note explaining why.
- In `deep` mode, if a high-risk semantic gate is `partial`, `blocked`, `invalidated`, or absent, create at least one coverage-debt note tied to the gate or proof obligation.
- If a material observation remains unrouted because the model shape is unknown, either route it to a working hypothesis / skill optimization suggestion or create coverage debt tied to the observation.
