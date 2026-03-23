# PoC Standard

A PoC must prove exploitability with the least risky, most reproducible method available.

---

## Required Quality Bar

- Use the smallest payload or step sequence that demonstrates the issue clearly.
- Prefer non-destructive verification over destructive exploitation.
- Tie the PoC directly to the reported impact and affected location.
- State any assumptions, prerequisites, or required privileges.
- Include expected success signals so another reviewer can validate the result.

---

## Required Fields

- entry point or trigger path
- exact payload, request, or step sequence
- preconditions such as auth level, feature flag, seed data, or API version
- expected success signal: response diff, timing delta, state change, callback, or log evidence
- safety note if the PoC can modify data, invoke outbound traffic, or trigger expensive work

---

## Practical Rules

- Critical and High findings require a concrete PoC unless the environment makes reproduction impossible.
- Medium findings should include a concise reproduction path when feasible.
- If a runtime PoC is unsafe, provide a code-level proof plus the minimal runtime confirmation signal.
- For versioned APIs, specify which versions were tested and whether older versions are weaker.
- For multi-step exploits, separate the steps and identify the first privilege boundary crossed.

---

## Avoid

- payload dumps without context
- overly destructive proof such as dropping tables when a boolean condition proves SQLi
- generic scanner output with no mapping to the actual code path
- saying "theoretically exploitable" without showing the shortest credible exploit path
