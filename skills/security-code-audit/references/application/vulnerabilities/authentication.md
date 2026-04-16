# Authentication Vulnerabilities

Authentication flaws let attackers impersonate users, mint or reuse tokens, or take over sessions and recovery flows.

Focus on proving identity:
- login
- session creation and rotation
- password reset and recovery
- JWT / API key verification
- MFA and step-up controls

---

## What To Enumerate First

1. login, refresh, logout, register, verify-email, invite, password-reset, OTP, and magic-link flows
2. every place sessions or bearer tokens are created or parsed
3. fallback or legacy auth paths, including `/v1/`, mobile APIs, admin routes, and internal tools
4. post-auth state changes such as password change, privilege elevation, or account recovery

---

## High-Risk Patterns

- accepting `alg: none` or attacker-selected JWT algorithms
- weak or hardcoded signing secrets
- missing token expiry or no audience / issuer validation
- the effective credential source differs across proxy, gateway, cookie, header, or query handling
- duplicate headers, cookies, or claims let one layer validate a different identity than another layer uses
- session fixation because IDs are not rotated on login
- unlimited reset or OTP attempts
- different error paths enabling username enumeration
- plaintext or reversible storage of recovery tokens

---

## Commonly Missed Cases

- one API version has rate limiting while another does not
- logout invalidates UI session but not API tokens
- password change does not revoke older sessions or refresh tokens
- remember-me or device tokens live much longer than intended
- MFA exists for web but not for mobile or support/admin flows
- reverse proxies or auth middleware inject trusted identity headers without strict edge-only guarantees
- one layer verifies the token but another layer later trusts an unverified copy, fallback claim, or alternate transport
- first-win vs last-win behavior for duplicate `Authorization`, cookie, or identity headers changes the effective subject

---

## Root-Cause Lens

Do not define authentication bugs only by famous payloads such as `alg:none`.

Define them by the semantic failure:
- the application authenticates a different subject than the developer intended
- token validity, assurance level, or credential source changes across layers
- one layer verifies stronger properties than the layer that actually chooses the user, session, or MFA state

This means review should focus on:
- which layer chooses the effective credential when the same request carries cookie, header, query, or forwarded identity data
- whether proxy, gateway, framework, JWT library, and application code all parse the same token and claims the same way
- whether signature validation, session lookup, MFA state, and privilege elevation all operate on the same canonical subject

Public JWT POCs are useful because they expose these differences.
The root cause is identity interpretation drift, not a single token string.

---

## Dangerous Patterns

```python
jwt.decode(token, options={"verify_signature": False})
app.secret_key = "changeme"
```

```javascript
jwt.verify(token, secret)
const secret = process.env.JWT_SECRET || "dev-secret"
```

```java
http.csrf().disable();
NoOpPasswordEncoder.getInstance();
```

---

## Safe Patterns

- explicit JWT algorithm allowlists and complete claim validation
- strong secrets from environment or a key manager only
- password hashing with bcrypt, argon2, scrypt, or framework defaults built on them
- session rotation after login and privilege changes
- tight TTLs plus rate limiting for reset, OTP, and magic-link endpoints

---

## Audit Questions

- Can the same token be replayed after password reset or role change?
- Are auth checks consistent across browser, mobile, API, and admin interfaces?
- Can an attacker distinguish "invalid user" from "invalid password"?
- Does failure handling accidentally skip signature or expiry verification?
- Which layer chooses the active identity if the same request carries multiple credential sources?
- Can gateway, middleware, library, and application code derive different subjects or assurance levels from the same request?
- Are cookies marked `Secure`, `HttpOnly`, and `SameSite`?

---

## Grep Starting Points

```bash
grep -rn 'jwt|JWT|token|refresh|session|remember|magic|otp|reset' .
grep -rn 'verify_signature.*False|algorithms=\\[\"none\"\\]|ignoreExpiration|NoOpPasswordEncoder' .
grep -rn 'SECRET_KEY|JWT_SECRET|session secret|remember_token' .
grep -rn 'rateLimit|throttle|lockout|captcha|attempts' .
```

---

## Related References

- `references/application/exploits/jwt.md`
- `references/application/vulnerabilities/api-security.md`
