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
- Verify that the proposed fix preserves legitimate control flow before calling it "minimal."
- For Solidity and smart-contract findings, verify that the proposed fix is compatible with the active `pragma`, the actual configured compiler version, and the imported dependency version.
- Do not recommend newer language or library features such as custom errors, newer OZ access-control helpers, or syntax-level refactors unless the current build can support them without an explicit upgrade plan.
- Treat compiler and dependency reality as compatibility context, not as an automatic reason to dismiss a vulnerability. Only narrow or downgrade a finding when the version difference actually changes semantics, and say exactly how.
- Do not recommend reusing the same reentrancy guard or lock on a synchronous callback if an outer entrypoint already holds that guard and the callback is part of the intended execution path.
- For callback reentrancy in smart contracts, prefer fixes that remove attacker-controlled transfers from the callback, defer payout to a pull step, or add a dedicated callback-scoped guard/state machine that blocks nested entry without breaking the expected outer flow.
- If the smallest safe fix is not a one-line modifier change, say so explicitly instead of forcing an oversimplified patch.

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
- any execution caveats when the fix touches callbacks, flash-loan hooks, settlement ordering, or other synchronous external control transfers
- any compiler, library, or deployment caveats when the fix depends on a Solidity/OZ version change
