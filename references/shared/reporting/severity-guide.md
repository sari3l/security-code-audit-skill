# Severity Classification Guide

## Table of Contents
- [Severity Levels](#severity-levels)
- [Decision Matrix](#decision-matrix)
- [Rubric Overlay](#rubric-overlay)
- [Common Patterns by Severity](#common-patterns-by-severity)

Apply `core/severity.md` first. Use this file for examples, tie-break context, and report phrasing.

## Severity Levels

### Critical
- Remote Code Execution (RCE)
- SQL injection on production database
- Authentication bypass
- Hardcoded admin credentials
- Unauthenticated access to sensitive data
- Exposed secrets (API keys, private keys) in public repos

### High
- Stored XSS in user-facing applications
- IDOR allowing access to other users' data
- Privilege escalation (user → admin)
- Insecure deserialization
- JWT with `alg: none` accepted
- SSRF with internal network access
- Path traversal with file read/write

### Medium
- Reflected XSS
- CSRF on state-changing actions
- Missing rate limiting on authentication
- Verbose error messages exposing internals
- Outdated dependencies with known CVEs (non-critical)
- Missing security headers
- Weak password policy

### Low
- Information disclosure (server version, framework info)
- Missing `HttpOnly` / `Secure` flags on non-sensitive cookies
- Clickjacking on non-sensitive pages
- Self-XSS (requires social engineering)
- Minor misconfigurations with no direct exploit path

### Informational
- Security best practice suggestions
- Defense-in-depth recommendations
- Code quality issues with potential security implications
- Missing monitoring / logging

## Decision Matrix

When assigning severity, consider these factors:

| Factor | Increases Severity | Decreases Severity |
|--------|-------------------|-------------------|
| Exploitability | Easy, no auth needed | Requires complex chain |
| Impact | Data breach, RCE | Info disclosure only |
| Scope | Affects all users | Affects single user |
| Data sensitivity | PII, financial, health | Public data |
| Attack surface | Internet-facing | Internal only |
| Authentication | Pre-auth | Post-auth, admin only |

## Rubric Overlay

Use the lightweight rubric from `core/severity.md` before choosing the final label.

- Higher exploitability, broader scope, and lower required privileges push the score up.
- Proven exploit chains beat hypothetical chains.
- When two levels are both plausible, prefer the lower one unless evidence clearly supports the higher level.

## Common Patterns by Severity

### SQL Injection Severity Depends on Context
- **Critical**: Direct database access, no WAF, contains sensitive data
- **High**: Behind authentication, limited data access
- **Medium**: Read-only queries, non-sensitive data

### XSS Severity Depends on Context
- **High**: Stored XSS in shared content (comments, profiles)
- **Medium**: Reflected XSS, requires user interaction
- **Low**: Self-XSS, DOM-based with limited impact

### Dependency Vulnerabilities
- **Critical**: Known RCE exploit in the wild
- **High**: Known exploit, requires specific conditions
- **Medium**: Known vulnerability, no public exploit
- **Low**: Theoretical vulnerability, very old CVE with no known exploitation

### Logging And Monitoring
- **High**: logs expose reusable credentials, tokens, reset links, or admin-only data at broad scope
- **Medium**: PII or sensitive workflow data logged without masking but access is somewhat constrained
- **Low**: missing alerting or thin audit logging with no direct exploit path

### Infrastructure And IaC
- **Critical**: public or trivial path to root-like container compromise, exposed admin plane, or broad secret disclosure
- **High**: privileged container, wildcard cloud access, public bucket with sensitive data, or externally reachable insecure management service
- **Medium**: mutable image tags, weak resource controls, overly broad network exposure without proven direct compromise
- **Low**: hygiene issues that do not currently expose a direct path
