# Cryptographic Vulnerabilities

Cryptographic issues usually come from choosing the wrong primitive, using the right primitive incorrectly, or mishandling keys and randomness.

Focus on:
- password hashing
- token signing
- randomness
- key storage and rotation
- TLS and certificate validation

---

## High-Risk Patterns

- MD5 / SHA1 for passwords or security-sensitive integrity checks
- `rand()`, `Math.random()`, timestamps, or UUIDs as secrets
- hardcoded AES keys, JWT secrets, IVs, or salts
- ECB mode or encryption without integrity
- disabled certificate validation

---

## Commonly Missed Cases

- strong hash used without a password-hardening algorithm
- secure algorithm but attacker-controlled key source
- key rotation missing on environment cloning or incident response
- secret comparison using ordinary equality instead of constant-time comparison
- signing tokens correctly but failing to validate claims or trust boundaries

---

## Dangerous Patterns

```python
hashlib.sha256(password.encode()).hexdigest()
```

```javascript
const token = Math.random().toString(36)
```

```csharp
var rng = new Random()
```

---

## Safe Patterns

- password hashing with bcrypt, argon2, scrypt, or framework-backed PBKDF
- CSPRNGs for tokens and secrets
- environment or KMS-backed secrets
- authenticated encryption and safe defaults from vetted libraries
- strict TLS certificate and hostname validation

---

## Audit Questions

- Where do secrets originate, and how are they rotated?
- Are password hashes tunable and actually expensive enough?
- Are HMAC, JWT, and webhook secrets compared in constant time?
- Can staging or source access recover production signing material?
- Does any HTTP client skip certificate verification?

---

## Grep Starting Points

```bash
grep -rn 'md5|sha1|Math\\.random|rand\\(|Random\\(|mt_rand|uniqid' .
grep -rn 'bcrypt|argon2|scrypt|password_hash|PasswordHasher|Rfc2898DeriveBytes' .
grep -rn 'SECRET|private key|signing key|JWT_SECRET|AES|CipherMode\\.ECB|verify=False|InsecureSkipVerify|danger_accept_invalid' .
grep -rn 'timingSafeEqual|hash_equals|ConstantTimeCompare|secure_compare|FixedTimeEquals' .
```

---

## Related References

- `references/application/vulnerabilities/authentication.md`
- `references/application/vulnerabilities/data-exposure.md`
