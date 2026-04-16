# Finding Detail Standard

Each finding entry should be specific enough that another engineer can reproduce, triage, and fix it without re-running the entire audit.

---

## Required Fields

- `Severity`
- `Maturity`
- `Category / Surface`
- `Fingerprint`
- `Location`
- `Status`
- `Description`
- `Attack Vector`
- `Impact`
- `PoC`
- `Evidence`
- `Minimal Fix`
- `Hardening`
- `Related Findings`

## Optional Context Fields

- `Build Context`
  Use for smart-contract findings when `pragma`, actual compiler, optimizer, proxy model, or key dependency version materially affects exploitability, severity confidence, or remediation compatibility.

---

## Writing Rules

- Keep the description factual and exploit-centered.
- Use real file paths and line numbers from inspected code.
- List all affected locations when the same pattern repeats.
- Keep the fingerprint stable across line moves and refactors when the exploit path is still the same.
- Group multiple downstream exploit paths into one finding only when the failed control, trust boundary, and minimal fix are materially shared.
- Keep operator-significant exploit paths obvious in the title, `Attack Vector`, `Impact`, `Related Findings`, and attack-chain narrative without splitting findings by default.
- Quote only the minimum relevant code needed to prove the issue.
- Distinguish direct impact from chain impact if the issue compounds with others.
- Main finding entries should use `Maturity: Confirmed`.
- Candidate entries belong in a separate `Candidate Signals` section and should follow `evidence-standard.md`.
- `Minimal Fix` must be exploit-breaking and execution-preserving; avoid proposing patches that would self-revert or disable the intended happy path.
- `Build Context` is advisory context, not a dismissal mechanism. Use it to sharpen exploitability and remediation accuracy, not to auto-close a finding just because the repo is on an older or newer compiler line.
- Use `Pending historical validation` only when the finding is confirmed but lifecycle labels are withheld because the post-scan historical-miss gate failed for the run.

---

## Minimal Entry Shape

```markdown
### [SEV]-[NNN]: [Title]
- **Severity**: Critical / High / Medium / Low / Info
- **Maturity**: Confirmed
- **Category / Surface**: [C1-C12 label or smart-contract surface]
- **Fingerprint**: [stable finding fingerprint]
- **Location**: `file/path.ext:line`
- **Status**: New / Recurring / Regression / Pending historical validation
- **Description**: [What is wrong in the actual code path]
- **Attack Vector**: [Shortest credible exploit path]
- **Impact**: [What the attacker gains]
- **Build Context**: [Optional, only when version/dependency reality materially matters]
- **PoC**: [Concrete payload, request, or steps]
- **Evidence**:
  ```[lang]
  // Actual vulnerable code
  ```
- **Minimal Fix**: [Smallest real change that breaks exploitation]
  ```[lang]
  // Minimal patch
  ```
- **Hardening**: [Optional follow-up]
- **Related Findings**: [Cross references]
```
