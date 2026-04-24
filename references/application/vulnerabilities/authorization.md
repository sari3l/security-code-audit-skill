# Authorization Vulnerabilities

Authorization flaws happen when the application knows who the user is but fails to enforce what that user is allowed to access or change.

This includes:
- IDOR / BOLA
- horizontal privilege escalation
- vertical privilege escalation
- tenant-isolation failures
- route or action coverage gaps

---

## Audit Model

Authentication answers "who are you?"

Authorization answers "what can you do?"

Do not treat `is logged in` as equivalent to `is authorized`.

---

## What To Enumerate First

1. all routes and handlers taking object IDs, slugs, or tenant keys
2. all admin or staff-only actions
3. bulk operations, exports, downloads, and background actions
4. GraphQL nodes, nested resources, websocket events, and webhook-triggered actions

---

## High-Risk Patterns

- object lookups by `id` without owner or tenant scoping
- admin actions protected only in the UI
- middleware applied on some routes but not versioned or nested routes
- the policy checks one resource, tenant, or slug while the mutation later uses another representation or ID
- route, tenant, or object identity is canonicalized differently across gateway, router, serializer, cache, and data access layers
- batch operations validating the caller once but not every object
- global query filters bypassed by raw queries or explicit opt-outs

---

## Commonly Missed Cases

- read path is scoped, update/delete path is not
- file download endpoints skip ownership checks present in HTML pages
- internal service or webhook handlers assume upstream auth implies user auth
- support tooling has broader visibility than intended
- nested resource parents are checked, children are not
- policy checks a parent slug, path segment, or body field while the actual lookup uses a different child ID or internal key
- alternate routes, version selectors, or background handlers reach the same action without the same object-resolution path
- object or tenant scope is cached or preloaded under one canonical form and reused for another request shape

---

## Root-Cause Lens

Do not define authorization bugs only by `id=2` style IDOR probes.

Define them by the semantic failure:
- the application resolves a different subject, resource, action, or tenant than the policy was meant to protect
- the authorization check and the real data access or state change do not operate on the same canonical target
- one layer narrows scope, but a later layer re-expands it through a different identifier, route shape, or background path

This means review should focus on:
- where the protected object or tenant is first selected
- whether that same canonical object is the one actually read, mutated, exported, or deleted
- whether alternate transports, aliases, nested routes, background jobs, or admin tools resolve the same target differently

The payload is only the probe.
The root cause is subject-resource-action resolution drift.

---

## Dangerous Patterns

```python
invoice = Invoice.objects.get(id=invoice_id)
```

```javascript
const order = await Order.findById(req.params.id)
```

```java
documentRepository.findById(id).orElseThrow()
```

These patterns are only safe if scope is enforced elsewhere and actually verifiable.

---

## Safe Patterns

- query through user or tenant ownership relations
- explicit policy or role checks near the action
- per-object validation for bulk operations
- consistent authz enforcement across HTML, API, mobile, admin, and async paths

---

## Audit Questions

- If I swap the object ID, do I see another user's data?
- If I keep my token but alter the body or path tenant field, what changes?
- Can a low-privilege user hit a staff/admin action directly?
- Do v1 and v2 of the same endpoint enforce the same policy depth?
- Which field or route segment actually selects the protected object or tenant?
- Does the policy check the same canonical object that the final read, write, export, or delete step uses?
- Are file, export, and PDF endpoints scoped as tightly as JSON endpoints?

---

## Grep Starting Points

```bash
grep -rn 'findById|find\\(|get\\(id=|FindAsync\\(|objects\\.get\\(' .
grep -rn 'Authorize|authorize|can\\(|policy_scope|current_user_can|hasRole' .
grep -rn '/admin|isAdmin|role|tenant_id|owner_id|user_id' .
grep -rn 'bulk|export|download|destroy|delete|patch|update' .
```

---

## Related References

- `references/application/vulnerabilities/api-security.md`
- `references/application/exploits/idor.md`
