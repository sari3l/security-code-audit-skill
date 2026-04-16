# Mass Assignment Vulnerabilities

Mass assignment happens when client-controlled fields are copied into server-side models or entities more broadly than intended.

This often enables:
- role escalation
- ownership changes
- approval or verification bypass
- pricing, balance, or quota manipulation

---

## Where It Appears

- registration and profile update endpoints
- admin edit endpoints reachable through weak authz
- serializer or model helpers that accept all fields
- PATCH / merge-patch / JSON Patch handlers
- nested object writes in GraphQL or REST

---

## High-Risk Fields

- `role`, `isAdmin`, `permissions`
- `ownerId`, `userId`, `tenantId`
- `emailVerified`, `verified`, `approved`
- `balance`, `creditLimit`, `price`, `discount`, `plan`
- workflow or status fields such as `state`, `published`, `paid`

---

## Commonly Missed Cases

- blocklists instead of allowlists
- alternate field naming: `is_admin`, `isAdmin`, `admin`
- duplicate keys, alias fields, case-folding, or dash/underscore normalization changing which field wins
- nested writes through `profile`, `organization`, `membership`, or `settings`
- JSON, form-data, GraphQL, patch, and merge-patch handlers applying different binding or allowlist logic
- entity binding in internal/admin endpoints considered "safe"
- PATCH handlers or object mappers broader than create flows
- null, default, or merge semantics clearing server-controlled fields even when explicit assignment looks blocked

---

## Root-Cause Lens

Do not define mass assignment by a short list of famous field names alone.

Define it by the semantic failure:
- attacker-controlled structure is reduced into server state more broadly than intended
- the binder, serializer, mapper, or patch engine gives attacker input authority over server-owned fields
- different field aliases, encodings, content types, or merge rules end up targeting the same protected state

This means review should focus on:
- which request representations the application accepts: JSON, form, GraphQL, patch, multipart, nested objects
- how field names are normalized, aliased, flattened, or merged before persistence
- whether server-managed values are recomputed and then accidentally overwritten by a later generic merge

The payload is only the symptom.
The root cause is state-binding scope drift.

---

## Dangerous Patterns

```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
```

```javascript
await User.create(req.body)
await user.update(req.body)
```

```java
public ResponseEntity<?> update(@RequestBody User user) { ... }
```

---

## Safe Patterns

- narrow DTOs or request structs
- explicit field allowlists
- read-only server-managed fields in serializers
- recomputation of prices, balances, roles, and ownership server-side

---

## Audit Questions

- Can the client set a field that only business logic should control?
- Do alternate casings or nested objects bypass field restrictions?
- Are mass-assignment protections consistent across create, update, bulk, and patch flows?
- Do different content types, duplicate keys, aliases, or merge semantics target the same protected field differently?
- Which binder or mapper performs the final write, and does it operate on the same allowlist the reviewer thinks exists?
- If a field is hidden in the UI, is it still accepted by the API?

---

## Grep Starting Points

```bash
grep -rn '__all__|permit!|\\$request->all\\(|req\\.body|TryUpdateModelAsync|BindJSON|ShouldBindJSON' .
grep -rn 'role|is_admin|isAdmin|tenant_id|owner_id|balance|credit_limit|approved' .
grep -rn 'JsonPatchDocument|merge-patch|assign_attributes|fill\\(|forceFill\\(' .
```

---

## Related References

- `references/application/exploits/mass-assignment.md`
- `references/application/vulnerabilities/business-logic.md`
- `references/application/vulnerabilities/pricing-and-accounting.md`
