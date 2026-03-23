# Application Coverage Matrix

## Purpose

Post-audit verification checklist for the application knowledge domain. After completing Phase 2, use this matrix to identify gaps before writing the final report.

If the active knowledge domain is `smart-contract`, use `references/smart-contract/vulnerabilities/coverage.md` instead of forcing a contract audit into this application matrix.

## Matrix

| # | Category | Key Questions | Covered? | Findings |
|---|----------|--------------|----------|----------|
| C1 | Injection | All execute/query calls checked? All user input traced to sinks? ORM raw queries reviewed? Template rendering with user data? OS command construction? Deserialization of untrusted data? Column name / ORDER BY injection? | | |
| C2 | Authentication | JWT config verified (algorithm, expiry, secret strength)? Password reset flow reviewed? All login code paths (including legacy/versioned)? MFA bypass possible? Session fixation? Token rotation on privilege change? Brute force protection? Account lockout? Can a client downgrade to an older auth flow or weaker token path? | | |
| C3 | Authorization | Every endpoint has access control? IDOR checked on all resource lookups? Horizontal and vertical privilege escalation tested? Admin routes protected? Role hierarchy enforced? Multi-tenancy isolation? API version parity (v1/v2/v3 all checked)? Do older versions expose weaker field filtering or ownership checks? Are upload replace, delete, export, download, and presigned URL issuance bound to the correct user or tenant? | | |
| C4 | Mass Assignment | All create/update endpoints checked for unprotected fields? Role/admin/permission fields guarded? ORM model-level protection (allowlist vs blocklist)? Nested object assignment? Bulk update endpoints? Are filenames, object keys, storage paths, and archive extract paths server-controlled or safely constrained? Are size, count, and overwrite protections enforced? | | |
| C5 | Data Exposure | Passwords hashed with bcrypt/argon2? No secrets in source code? GitHub/GitLab tokens, cloud AK/SK, private keys, connection strings, usernames/passwords, or internal IPs/hostnames hardcoded? PII encrypted at rest? TLS enforced? Sensitive headers (HSTS, no-cache for auth pages)? API keys rotated? Verbose error messages? Stack traces in responses? Are signed download URLs, export tokens, or attachment links guessable or replayable? | | |
| C6 | Misconfiguration | Debug mode off in production? Default credentials changed? Error messages generic? Security headers present? Directory listing disabled? CORS restrictive? Cookie flags (HttpOnly, Secure, SameSite)? `.env`, proxy, CI, and runtime config reviewed? | | |
| C7 | XSS | All template outputs escaped? Raw/unescaped rendering justified? CSP header present? DOM-based XSS in client JS? Stored XSS via database fields? SVG/HTML file upload? All template engines checked (Jinja2, EJS, Handlebars, etc.)? | | |
| C8 | Dependencies | Dependency audit path chosen per detected ecosystem? Native or repo-configured audit command run where available? Lock file reviewed? EOL frameworks/libraries? Transitive dependencies reviewed? Vendored/base-image risk reviewed where relevant? External SCA results normalized if present? Tooling blockers recorded if audit could not run? | | |
| C9 | Cryptography | CSPRNG used for tokens? No MD5/SHA1 for passwords? TLS 1.2+ enforced? No hardcoded keys/IVs? Certificate validation enabled? Key length adequate (RSA >= 2048, AES >= 128)? Timing-safe comparison for secrets? | | |
| C10 | SSRF | All URL-fetching endpoints checked? Internal network access blocked? DNS rebinding mitigated? Allowlist vs blocklist for target URLs? Cloud metadata endpoint (169.254.169.254) blocked? Redirect following restricted? Can unrestricted upload, archive extraction, or storage fetch paths become server-side file write/read primitives? | | |
| C11 | Logging & Monitoring | `references/application/vulnerabilities/logging-monitoring.md` loaded? No credentials in logs? No PII in logs without masking? Log injection prevented? Audit trail for auth events? Alerting on repeated failures? Log files access-controlled? Security events logged? | | |
| C12 | Infrastructure (IaC) | `references/application/vulnerabilities/infrastructure.md` loaded when IaC exists? Container runs as non-root? Secrets not in Dockerfiles? Network policies defined? Resource limits set? Image pinned to digest? No privileged mode? Helm values reviewed? Terraform state secured? Compose and Kubernetes manifests reviewed? | | |

## Coverage Standards

- **Mandatory**: C1, C2, C3, C5, C7 must reach a check mark for any web application
- **Mandatory**: C4 must be checked if any create/update endpoints exist
- **Conditional**: C10 only if any URL-fetching or webhook functionality exists
- **Conditional**: C12 only if IaC files (Dockerfile, docker-compose.yml, k8s manifests, terraform) are present
- **Conditional**: C8 only if lock files (package-lock.json, go.sum, requirements.txt, pom.xml) are present
- **Template check**: Did you scan ALL template/view files? This is mandatory regardless of scope.
- **API versions**: Did you check ALL /v1/, /v2/, /v3/ variants? Legacy versions often lack newer security controls and may permit downgrade paths.
- **Coverage debt**: If a category is partial, blocked, invalidated, or time-boxed, record it using `references/shared/reporting/coverage-debt-standard.md` instead of marking it clean.

## Audit Strategy by Category

### Sink-driven (C1, C7)

Trace user inputs to dangerous functions. Start from the sinks and work backward.

1. Grep for all dangerous sinks (SQL execute, OS command, eval, innerHTML)
2. For each sink, trace the data flow backward to find user-controlled input
3. Verify sanitization/parameterization exists on every path

### Control-driven (C2, C3, C4)

Check that access controls exist on every endpoint.

1. List all routes/endpoints from router definitions
2. For each endpoint, verify authentication middleware or decorator is present
3. For each endpoint accepting a resource ID, verify ownership check exists
4. Check for admin-only routes accessible without admin role
5. For each create/update endpoint, verify field-level protection against mass assignment

### Config-driven (C6, C8, C9, C12)

Review settings files and defaults.

1. Read all config/settings files, including `.env*`, Docker, compose, proxy, ingress, CI, and orchestrator manifests
2. Check environment-specific overrides (dev vs prod)
3. Verify secure defaults are not overridden
4. Run the dependency audit path defined by the matching `references/shared/dependencies/` module, or record the blocker and review lock files manually

### Logic-driven (C5, C10, C11)

Understand business rules and data flows.

1. Identify where sensitive data enters the system
2. Trace sensitive data through processing, storage, and output
3. Verify encryption, masking, and access controls at each stage
4. Check all outbound request endpoints for SSRF
5. Check logging calls near sensitive data handling

## Termination Criteria

### Quick Audit
- All high-risk patterns scanned via grep
- C1 and C7 sinks enumerated
- C2 and C3 spot-checked on critical endpoints
- No deep data-flow tracing required

### Standard Audit
- 10 out of 12 categories (or all applicable) at check mark
- Remaining categories at warning with written justification
- All critical/high findings documented with reproduction steps
- Template files and API versions fully covered
- Each endpoint × vulnerability type treated as separate finding

### Deep Audit
- All applicable categories at check mark
- Data flow traced end-to-end for every user input
- Dependency tree fully reviewed (including transitive)
- Infrastructure configs reviewed line by line
- Business logic edge cases explored
- Attack chains documented for compound risks
