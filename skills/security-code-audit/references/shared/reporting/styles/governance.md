# Governance Report Style

Use this style when the report should optimize for long-term remediation governance, audit-lifecycle tracking, historical comparison, and regression reuse.

---

## Core Intent

- keep the report root-cause-first
- preserve the current standardized audit scaffold
- help engineering and security teams understand which shared control failure removes the most downstream risk

This is the preferred internal-reference report for history matching and regression baselines when both styles exist for the same timestamp family.

---

## Required Invariants

- keep the same evidence discipline as every other style
- keep `Fingerprint`, `Status`, `Candidate Signals`, `Coverage Debt`, `Historical Context`, and supplemental sections when material
- do not hide the most dangerous exploit path, but do not force every downstream consequence into its own standalone finding when the remediation boundary is shared

---

## Finding Boundary Rules

- one governance finding may group multiple downstream exploit paths when:
  - the failed control is materially the same
  - the trust boundary is materially the same
  - the minimal fix is materially the same
- grouping is encouraged when splitting would exaggerate severity counts without changing the remediation plan
- when a key exploit path is operationally important, surface it clearly in `Attack Vector`, `Impact`, `PoC`, `Related Findings`, or `Attack Chains`

---

## Title And Summary Rules

- titles should name the root cause or failed control first
- summaries should call out when one fix removes multiple downstream exploit paths
- top findings should help a reviewer prioritize remediation governance, not just dramatic exploit phrasing

---

## Attack Chain Rules

- attack chains should recover the downstream paths grouped under a shared root cause
- chain sections may reference grouped findings and explain how multiple attacker actions collapse into one governance problem
- use attack chains to keep exploit visibility high without fragmenting the confirmed finding list unnecessarily
