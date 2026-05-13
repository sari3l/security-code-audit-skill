# Surface Profile Standard

Create one compact surface profile during recon. Reuse it to drive loading, delegation, and coverage.

Also create a compact advisory `code_fact_snapshot` for audit state. The snapshot gives AI a stable code map, but it must not limit AI exploration or prove that unlisted behavior is absent.

`code_fact_snapshot` is advisory, compact, and non-authoritative. It is not a closed intermediate representation, a mandatory schema that every finding must fit, or a full static-analysis database.

## Purpose

The surface profile is the smallest shared map of what the repo actually contains.

Use it to:
- route lazy loading
- avoid re-reading the whole repo map in later phases
- give workers compact context in multi-agent mode
- explain why a module was or was not loaded

Use `code_fact_snapshot` to:
- preserve observed entrypoints, routes, candidate sources, candidate sinks, state transitions, artifact surfaces, and parser notes
- make quick incremental comparisons and multi-agent handoffs more precise
- record limitations when dynamic, generated, reflected, framework-magic, or artifact-mediated behavior cannot be fully mapped

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

## Advisory Code Fact Snapshot

Store the snapshot in audit state, not in the user-facing surface profile.

Prefer:
- `file_inventory`
- `entrypoints`
- `routes`
- `security_relevant_functions`
- `source_candidates`
- `sink_candidates`
- `state_transition_candidates`
- `dependency_manifests`
- `artifact_surfaces`
- `parser_notes`
- `limitations`

Hard rules:
- keep it compact and evidence-referenced
- do not require whole-program call graphs or IDE-grade symbol resolution
- missing facts are limitations, not safety proof
- if a security-relevant fact does not fit the fields, preserve it with `extensions` or an `evidence_observations` entry using a `schema_gap`, `unstructured_hypothesis`, or `custom:*` label
- never discard a finding candidate, trace clue, or unfamiliar security signal merely because it does not fit the preferred snapshot fields

## Update Rules

- Create it once in stage `2/6`.
- Update it only when a materially new surface appears.
- Do not let it grow into a route inventory or finding list.
- Share this profile, not the whole recon dump, with worker agents.
- Update the advisory `code_fact_snapshot` as materially new facts or limitations appear, but do not let it become a second report or a mandatory exhaustive static-analysis database.

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
