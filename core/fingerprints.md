# Finding Fingerprint Standard

Use stable finding fingerprints for history matching, dedupe, and multi-agent merge.

Fingerprints are the canonical finding identity. Markdown display IDs such as
`[HIGH]-001` are presentation labels derived later from sorted canonical
findings; they are not identities and must not be used for history matching.

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
- Use route or resource families such as `user-profile update`, `admin user delete`, or `invoice object read`.
- Use trust boundaries such as `public -> app`, `user -> admin`, `tenant A -> tenant B`, or `app -> metadata service`.
- Normalize wording variants that describe the same failed control, for example `pause-unpause::no-events`, `pause::custom-no-event`, and `pause::no-events-no-pausable` when the real issue is the same missing observable pause-state transition.

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
- the wording differences are presentation-only and do not change the failed control being remediated

## Usage

- Compute a fingerprint before assigning `New`, `Recurring`, or `Regression`.
- Write each confirmed finding to `findings.jsonl` with its fingerprint before
  generating Markdown.
- Derive Markdown display IDs by sorting canonical findings by severity rank,
  category/surface, then fingerprint, and numbering within each severity.
- Do not derive display IDs from discovery order, worker return order, report
  history order, or human-edited report order.
- Use it to merge worker output in multi-agent mode.
- Use it to avoid double counting native dependency audit results and external SCA results.
- If the fingerprint is uncertain, keep the finding separate until evidence is stronger.
