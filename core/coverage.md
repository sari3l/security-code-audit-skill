# Coverage Controls

Use this file to minimize shallow scans, skipped surfaces, and false negatives.

## Hard Rules

- One hit is never enough; search for every recurring pattern across the repo.
- Do not stop at backend handlers; templates, views, jobs, config, and storage paths matter too.
- Check all relevant API versions, legacy routes, alternate transports, and admin paths.
- When uploads, exports, webhooks, background jobs, or object storage exist, include them explicitly in scope.
- Coverage is not complete until the audit state contains counted totals for `applicable`, `reviewed`, `partial`, `blocked`, `invalidated`, and `time_boxed`.
- Every security-relevant function or state-changing transition in scope must have a bounded function-chain record or an explicit coverage-debt entry.
- In `quick`, `standard`, and `deep`, prior findings touching the same helper, sink, route family, or trust boundary must be reopened against current code before they can be counted as covered or fixed.
- A still-live prior vulnerability that the current scan missed is a historical miss, not a valid clean comparison; record it as coverage debt and emit `Skill Optimization Suggestions`.

## Exhaustiveness Rules

- Enumerate sensitive operations before choosing sample files.
- Complete each applicable category before calling the scan covered.
- If a category is shallow, record the blocker or why it was not applicable.
- For repeated bug classes, list all affected locations or explicitly justify grouping.

## False-Negative Controls

- Do not skip a category because another one already produced findings.
- Do not let known CVEs or past issues bias you away from less obvious categories.
- Do not assume one framework path represents all versions or route groups.
- Do not treat client-side limits, WAFs, or proxy rules as proof that server-side controls exist.

## Stop Conditions

Do not finish the audit until:
- applicable categories are covered or explicitly blocked
- templates and views were considered where relevant
- API version parity was checked where versions exist
- dependency and config surfaces were reviewed when present
- counted coverage totals reconcile with the report summary
- in-scope function chains are either recorded as bounded/open/blocked/invalidated or explicitly carried as coverage debt
- historical `Fixed` claims affecting in-scope current code were explicitly reopened or carried as coverage debt
- deferred history replay either found no historical misses, or every historical miss is recorded with coverage debt, `Skill Optimization Suggestions`, and a withheld lifecycle comparison
