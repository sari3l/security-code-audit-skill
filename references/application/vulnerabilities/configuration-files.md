# Configuration File Vulnerabilities

Configuration files frequently contain the real security posture of the system, even when the application code looks safe.

Focus on files such as:
- `.env`, `.env.*`, `application.yml`, `application.properties`, `appsettings*.json`
- `Dockerfile`, `docker-compose*.yml`, `compose*.yaml`
- Kubernetes manifests, Helm values, Terraform, cloud config
- `nginx.conf`, Caddy, Traefik, Apache, ingress definitions
- CI/CD workflows, startup scripts, Procfiles, systemd units

---

## High-Risk Patterns

- committed secrets, tokens, private keys, or example credentials
- `DEBUG=true`, dev exception pages, or verbose logging in production config
- containers running as root, `privileged: true`, host networking, writable mounts, broad capabilities
- proxy trust mistakes that let attackers spoof client IPs or bypass rate limits
- overly broad CORS, wildcard hosts, disabled TLS validation, insecure cookie defaults

---

## Commonly Missed Cases

- `.env.example` or sample config still contains usable secrets or admin accounts
- production overrides live in compose, Helm values, or CI variables rather than app config files
- reverse-proxy headers differ between environments, changing auth or rate-limit behavior
- build-time secrets leak through Docker layers, image history, or copied files
- old versioned routes remain mounted through ingress even after code-level deprecation

---

## Dangerous Patterns

```dockerfile
FROM node:20
USER root
COPY . .
ENV JWT_SECRET=dev-secret
```

```yaml
services:
  app:
    privileged: true
    env_file:
      - .env
```

```env
DEBUG=true
AWS_SECRET_ACCESS_KEY=AKIA...
```

```nginx
proxy_set_header X-Forwarded-For $http_x_forwarded_for;
add_header Access-Control-Allow-Origin *;
```

---

## Safe Patterns

- keep secrets out of repo-tracked config files
- separate dev and prod config with explicit secure prod defaults
- run containers as non-root with minimal capabilities and mounts
- terminate and trust proxy headers only from known upstreams
- review versioned ingress and route config for stale exposure

---

## Audit Questions

- Which config files actually control production behavior?
- Are secrets or default credentials committed anywhere, including examples and CI files?
- Can proxy or ingress settings weaken auth, rate limiting, or host validation?
- Do Docker or Kubernetes settings expand filesystem, network, or privilege boundaries?
- Do older API versions remain exposed through gateway or ingress config after deprecation?

---

## Grep Starting Points

```bash
find . \\( -name '.env*' -o -name 'Dockerfile*' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'application*.yml' -o -name 'application*.properties' -o -name 'appsettings*.json' -o -name '*.tf' -o -name 'values*.yaml' -o -name 'Chart.yaml' -o -name 'nginx*.conf' -o -name 'Caddyfile' -o -path '*/.github/workflows/*' \\)
grep -rn 'DEBUG|APP_DEBUG|NODE_ENV|Development|UseDeveloperExceptionPage|debug=True' .
grep -rn 'SECRET|TOKEN|PASSWORD|KEY|PRIVATE_KEY|AWS_' .
grep -rn 'privileged: true|hostNetwork: true|runAsUser: 0|allowPrivilegeEscalation: true|CAP_SYS_ADMIN' .
grep -rn 'Access-Control-Allow-Origin|AllowAnyOrigin|X-Forwarded-For|trusted_proxies|proxy_set_header' .
```

---

## Related References

- `references/application/vulnerabilities/security-misconfiguration.md`
- `references/application/vulnerabilities/data-exposure.md`
- `references/shared/reporting/coverage-matrix.md`
