# Finding Fingerprint Standard

Use stable finding fingerprints for history matching, dedupe, and multi-agent merge.

## Canonical Fields

Derive a fingerprint from:
- category
- vulnerability family
- sink or failed control
- route family or resource family
- trust boundary
- privilege context

## Construction Rules

- Prefer stable semantics over file paths.
- Do not include line numbers.
- Do not include severity.
- Do not include issue titles written for humans.
- Do not include report style.
- Use route or resource families such as `user-profile update`, `admin user delete`, or `invoice object read`.
- Use trust boundaries such as `public -> app`, `user -> admin`, `tenant A -> tenant B`, or `app -> metadata service`.

## When To Split

Use different fingerprints when:
- remediation differs
- the vulnerable control is different
- the affected resource family is different
- the privilege boundary is different

## When To Merge

One fingerprint may cover multiple locations only when:
- the vulnerability family is the same
- the exploit path is materially the same
- the fix is materially the same

One governance finding may map to multiple exploit-first presented findings only when the shared fingerprint logic still holds. If splitting the presentation would require different fingerprints under these rules, keep them as different underlying issues.

## Usage

- Compute a fingerprint before assigning `New`, `Recurring`, or `Regression`.
- Use it to merge worker output in multi-agent mode.
- Use it to avoid double counting native dependency audit results and external SCA results.
- Keep the same fingerprint across governance and exploit-first reports when the underlying issue is materially the same.
- If the fingerprint is uncertain, keep the finding separate until evidence is stronger.
