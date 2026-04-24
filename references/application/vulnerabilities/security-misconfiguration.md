# Security Misconfiguration

Security misconfiguration is the category for insecure defaults, over-broad trust, and dangerous environment or deployment settings.

Typical examples:
- debug mode in production
- permissive CORS
- missing cookie flags or security headers
- exposed admin/diagnostic tooling
- unsafe `.env`, container, proxy, ingress, or CI settings

---

## What To Enumerate First

1. environment and settings files such as `.env*`, `application*.yml`, `appsettings*.json`, and framework settings
2. web server, proxy, ingress, container, compose, and orchestration config
3. CI/CD, startup, and deployment manifests that influence runtime security
4. debug and diagnostics endpoints
5. cookie, session, header, and CORS configuration

---

## High-Risk Patterns

- `DEBUG=true`, framework dev mode, interactive consoles
- `Access-Control-Allow-Origin: *` with credentials
- missing `Secure`, `HttpOnly`, `SameSite` on auth cookies
- broad host allowlists or disabled host validation
- exposed Swagger, Actuator, mail previews, job dashboards, or admin consoles
- committed secrets or default credentials in `.env`, compose, Helm, or CI files
- containers running as root, `privileged`, or with unsafe mounts/capabilities
- proxy trust mistakes that allow `X-Forwarded-For` spoofing or header confusion

---

## Commonly Missed Cases

- secure prod defaults overridden by `.env.local`, Helm values, or compose files
- only one ingress or proxy path injects security headers
- diagnostics disabled in UI but still reachable directly
- development secrets and sample accounts left enabled
- upload or temp directories writable and executable
- API gateways or ingress rules still expose deprecated versioned endpoints
- build-time secrets leak through Docker layers or copied files

---

## Safe Patterns

- explicit production config reviewed separately from dev defaults
- restrictive CORS and host validation
- secure session and cookie attributes everywhere
- disabled or authenticated diagnostics
- separate secrets per environment
- non-root containers with minimal privileges
- reviewed proxy and ingress trust boundaries

---

## Audit Questions

- What happens if the app starts with no environment overrides at all?
- Are there multiple deployment paths with different header or cookie handling?
- Can a browser on another origin send credentialed requests successfully?
- Are any debug or health endpoints exposing internal data or controls?
- Which repo-tracked config files actually influence production behavior?
- Do Docker, compose, Kubernetes, or proxy files weaken auth, rate limiting, or version gating?

---

## Grep Starting Points

```bash
find . \( -name '.env*' -o -name 'Dockerfile*' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'application*.yml' -o -name 'application*.properties' -o -name 'appsettings*.json' -o -name 'values*.yaml' -o -name 'Chart.yaml' -o -name 'nginx*.conf' -o -name 'Caddyfile' -o -path '*/.github/workflows/*' \)
grep -rn 'DEBUG|APP_DEBUG|NODE_ENV|Development|UseDeveloperExceptionPage|debug=True' .
grep -rn 'CORS|Access-Control-Allow-Origin|AllowAnyOrigin|allow_credentials|origins "\\*"' .
grep -rn 'SameSite|HttpOnly|Secure|session_set_cookie_params|CookieAuthenticationOptions' .
grep -rn 'swagger|actuator|telescope|debugbar|mailers|sidekiq|health' .
grep -rn 'SECRET|TOKEN|PASSWORD|KEY|PRIVATE_KEY|AWS_' .
grep -rn 'privileged: true|hostNetwork: true|runAsUser: 0|allowPrivilegeEscalation: true|CAP_SYS_ADMIN' .
grep -rn 'X-Forwarded-For|trusted_proxies|proxy_set_header|real_ip_header' .
```

---

## Related References

- `references/application/vulnerabilities/data-exposure.md`
- `references/application/vulnerabilities/cryptography.md`
- `references/application/vulnerabilities/configuration-files.md`
