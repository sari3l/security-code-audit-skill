# Surface Profile Standard

Create one compact surface profile during recon. Reuse it to drive loading, delegation, and coverage.

## Purpose

The surface profile is the smallest shared map of what the repo actually contains.

Use it to:
- route lazy loading
- avoid re-reading the whole repo map in later phases
- give workers compact context in multi-agent mode
- explain why a module was or was not loaded

## Required Fields

Capture only observed surfaces:
- languages
- frameworks
- dependency ecosystems
- entrypoint types: web, API, CLI, worker, cron
- auth surface: session, JWT, API key, OAuth, MFA, reset flow
- versioned APIs or legacy paths
- templates or client-rendered views
- storage or file surface: upload, download, export, object storage, archives
- outbound fetch surface: webhooks, URL fetchers, callbacks, HTTP clients
- AI surface: LLM prompts, tool calls, retrieval, agent orchestration
- config and deployment surface: `.env`, Docker, compose, k8s, Helm, Terraform, CI
- logging and audit surface
- tenancy or role model if visible

## Output Shape

Keep the profile short and stable:

```text
[SURFACE PROFILE]
Languages: python, javascript
Frameworks: python_fastapi, javascript_nextjs
Dependencies: pip, npm
Entrypoints: api, worker
Auth: jwt, reset-flow
API Versions: v1, v2
Views: nextjs
File Surface: upload, presigned-download
Outbound Fetch: webhook, url-fetch
AI Surface: none
Config/IaC: .env, dockerfile, github-actions, k8s
Logging: app-logger, auth-events
Tenancy/Roles: single-tenant, admin/user
```

## Update Rules

- Create it once in stage `2/6`.
- Update it only when a materially new surface appears.
- Do not let it grow into a route inventory or finding list.
- Share this profile, not the whole recon dump, with worker agents.

## Routing Hints

Use the profile to decide what to load:
- auth or reset flows -> `references/application/vulnerabilities/authentication.md`
- object IDs, tenancy, admin roles, or version drift -> `references/application/vulnerabilities/authorization.md`
- create/update/binding surface -> `references/application/vulnerabilities/mass-assignment.md`
- templates, raw HTML, SVG, client rendering -> `references/application/vulnerabilities/xss.md` and `references/application/vulnerabilities/xss-templates.md`
- upload/download/object storage/archive surface -> `references/application/vulnerabilities/file-upload-download.md`
- outbound fetch or webhook surface -> `references/application/vulnerabilities/ssrf.md`
- manifests, lock files, images, or SCA artifacts -> `references/shared/dependencies/index.md`
- logging surface -> `references/application/vulnerabilities/logging-monitoring.md`
- Docker, k8s, Helm, Terraform, compose, cloud manifests -> `references/application/vulnerabilities/infrastructure.md` and `references/application/vulnerabilities/configuration-files.md`
- AI surface -> `references/application/vulnerabilities/injection.md` plus the exact sink-family modules involved
