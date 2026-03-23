# Coverage Controls

Use this file to minimize shallow scans, skipped surfaces, and false negatives.

## Hard Rules

- One hit is never enough; search for every recurring pattern across the repo.
- Do not stop at backend handlers; templates, views, jobs, config, and storage paths matter too.
- Check all relevant API versions, legacy routes, alternate transports, and admin paths.
- When uploads, exports, webhooks, background jobs, or object storage exist, include them explicitly in scope.

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
