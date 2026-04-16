# Evidence Standard

Use this standard to decide whether a suspicious pattern becomes a confirmed finding, remains a candidate signal, or is closed with negative evidence.

---

## Purpose

Evidence handling exists to reduce false positives without suppressing useful audit intuition.

This standard separates:
- `Confirmed Findings`
  Issues with enough code, exploitability, and impact evidence to enter the main findings list.
- `Candidate Signals`
  High-signal suspicious cases that still need stronger proof.
- `Negative Evidence`
  Concrete reasons a suspicious case was not promoted to a confirmed finding.

---

## Maturity Levels

### Confirmed

A finding is `Confirmed` only when the audit can point to:
- a real location in the current code or config
- a real vulnerable sink, control gap, or trust-boundary failure
- a credible attack vector
- a credible impact statement
- direct supporting evidence from inspected code

For privileged timing, rescue, or recovery concerns, `Confirmed` should also mean the current code leaves a realistic window where user-owned assets can actually be captured, stranded, or redirected despite the guards that are present today.

Critical and High findings should also include:
- a concrete PoC, or
- an explicit blocker that prevented safe proof but still leaves exploitability highly credible

For instruction-bearing artifacts such as `SKILL.md`, `AGENTS.md`, prompt templates, READMEs, or setup flows, `Confirmed` also means the artifact creates or preserves a credible operator-directed execution path, secret-access path, environment mutation path, or trust-boundary failure in the current repo behavior.

### Candidate

Keep a signal as `Candidate` when:
- the pattern is suspicious but exploitability is not yet proven
- the control path is incomplete or partially inferred
- the impact depends on assumptions not yet validated
- the environment or runtime gap blocks reliable confirmation
- the concern depends on a future refactor, hypothetical operator race, or an unproven "user funds remain stranded between transactions" premise
- the artifact contains a dangerous-looking command, keyword, or code block but the audit has not yet shown that the repo actually directs an operator or runtime to execute it
- the example is fenced, educational, or defensive and the surrounding context has not converted it into a live abuse path

Candidates do not belong in the main findings list.

### Closed With Negative Evidence

Close a candidate with negative evidence when the audit finds a concrete reason it should not be promoted, such as:
- the sink is unreachable from untrusted input
- effective parameterization or escaping is actually present
- authz or ownership checks exist on the true code path
- the dangerous helper is present but not attacker-controlled in the current usage
- the issue is mitigated by a real control, not by wishful inference
- existing phase guards, settlement order, or reentrancy locks already remove the claimed timing window in the current implementation
- the contract does not retain user-owned assets across transactions except under a state that was not actually proven reachable

---

## Promotion Rules

Promote `Candidate` to `Confirmed` only when the missing proof has been filled.

Do not promote based on:
- pattern match alone
- generic sink presence alone
- suspicious command text alone in instruction-bearing artifacts
- title similarity to a previous finding
- severity intuition without exploit-path evidence
- a purely theoretical future-refactor concern when the current code path already has concrete negative evidence

When in doubt:
- keep it as `Candidate`
- record the negative evidence or blocker
- note what would be needed to confirm it

## Instruction-Bearing Artifact Notes

For skill, agent, prompt, and setup repositories:

- plain mentions of `token`, `password`, `curl`, `sudo`, or `eval` in defensive prose are not confirmed findings by themselves
- a fenced or educational example remains `Candidate` unless surrounding context turns it into a real operator-directed execution path
- operator-risk findings should explain the instruction source, the execution or trust boundary, the affected asset or control surface, and the expected impact on the operator environment

---

## Required Candidate Notes

Every candidate should record:
- `Category / Surface`
- `Fingerprint`
- `Location`
- `Suspicion`
- `Why Not Confirmed Yet`
- `Negative Evidence or Blocker`
- `Next Verification Step`

---

## Minimal Candidate Shape

```markdown
### [CAND]-[NNN]: [Title]
- **Category / Surface**: [C1-C12 label or smart-contract surface]
- **Fingerprint**: [stable fingerprint]
- **Location**: `file/path.ext:line`
- **Suspicion**: [Why this still looks dangerous]
- **Why Not Confirmed Yet**: [What proof is missing]
- **Negative Evidence or Blocker**: [Real mitigating evidence or verification blocker]
- **Next Verification Step**: [What would confirm or reject this]
```

---

## Reporting Rules

- Main `Findings` section contains only `Confirmed` findings.
- `Candidate Signals` section contains unresolved high-signal cases.
- `Negative Evidence` may be attached to a candidate or summarized separately.
- Do not inflate candidate counts into confirmed severity totals.
