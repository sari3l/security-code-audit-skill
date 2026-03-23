# Sensitive Data Exposure

Sensitive data exposure is broader than cryptography alone. It includes any path where secrets, credentials, PII, or internal state become visible to the wrong party.

This covers:
- plaintext secrets in source or config
- verbose errors and stack traces
- over-broad serializers and exports
- exposed backups, logs, temp files, and debug endpoints

For deep repo-wide enumeration of tokens, cloud credentials, internal IPs, usernames/passwords, and other hardcoded sensitive literals, load `references/application/vulnerabilities/sensitive-hardcoding.md`.

---

## What To Enumerate First

1. secrets in code, config, `.env`, manifests, CI files, and build output
2. serializers, DTOs, export generators, and admin APIs
3. error handlers, debug pages, and logging sinks
4. file storage locations for uploads, backups, reports, and temp artifacts

---

## High-Risk Patterns

- `SECRET_KEY`, database passwords, private keys, and access tokens in source control
- stack traces or SQL errors returned to users
- APIs returning password hashes, reset tokens, or internal metadata
- public object-storage or static directories serving backups and report exports
- logs containing auth headers, cookies, raw request bodies, or payment data

---

## Commonly Missed Cases

- staging or QA config committed alongside production defaults
- presigned URLs or export IDs reusable across accounts
- `Debug` / `Serialize` derives or `toString()` methods leaking secrets
- exception reporters shipping request bodies to third parties
- environment dumps in `/proc/self/environ`, crash reports, or health endpoints

---

## Dangerous Patterns

```python
return JsonResponse(model_to_dict(user))
```

```javascript
res.json(user) // includes passwordHash, resetToken, internal flags
```

```php
phpinfo();
```

---

## Safe Patterns

- explicit serializer field lists
- generic user-facing errors with full details only in protected logs
- secrets from environment or a key manager, never source-controlled
- segregated storage for uploads, exports, and backups with least-privilege access

---

## Audit Questions

- If a route errors, what exactly comes back to the client?
- Are hidden or internal fields excluded explicitly, or just omitted in the UI?
- Can exports, file downloads, or signed URLs be guessed or replayed?
- Are secrets masked consistently in logs and telemetry?

---

## Grep Starting Points

```bash
grep -rn 'SECRET|PASSWORD|TOKEN|PRIVATE KEY|API_KEY|connectionString' .
grep -rn 'debug|phpinfo|stacktrace|printStackTrace|EnableSensitiveDataLogging|consider_all_requests_local' .
grep -rn 'res\\.json\\(|to_json|serializable_hash|Serialize|Debug' .
find . -name ".env" -o -name "*.sql" -o -name "*.bak" -o -name "*.zip"
```

---

## Related References

- `references/application/vulnerabilities/cryptography.md`
- `references/application/vulnerabilities/security-misconfiguration.md`
- `references/application/vulnerabilities/sensitive-hardcoding.md`
