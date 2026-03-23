# Remediation Standard

Every finding should recommend the smallest real change that closes the exploit path now.

---

## Required Structure

For each finding, split remediation into:
- `Minimal Fix`: the least disruptive code or config change that breaks exploitation
- `Hardening`: optional defense-in-depth work that reduces related future risk

If no small fix exists, say so explicitly and explain why a broader redesign is required.

---

## Minimal Fix Rules

- Patch the actual vulnerable sink, trust boundary, or authorization gap.
- Prefer narrow allowlists, parameterization, explicit field binding, or middleware placement fixes.
- Avoid recommending broad rewrites when a local fix is sufficient.
- Keep examples aligned with the project's actual framework and coding style.
- Explain why the proposed change stops the PoC, not just why it "looks safer."

---

## Hardening Rules

- Separate follow-up controls from the immediate fix.
- Hardening may include logging, rate limiting, CSP, additional validation, key rotation, or architectural cleanup.
- Do not present hardening as a substitute for closing the root exploit path.

---

## Validation Expectations

Each remediation should include:
- the specific condition that must become impossible after the fix
- a brief re-test note describing how to verify the PoC no longer works
- any rollout caveats such as data migration, backward compatibility, or legacy API impact
