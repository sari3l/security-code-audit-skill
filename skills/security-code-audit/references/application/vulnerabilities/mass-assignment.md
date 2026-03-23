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
- nested writes through `profile`, `organization`, `membership`, or `settings`
- entity binding in internal/admin endpoints considered "safe"
- PATCH handlers or object mappers broader than create flows

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
