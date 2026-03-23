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
