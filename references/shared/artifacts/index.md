# Artifact Review Index

This directory covers non-code artifacts that still shape security outcomes. These files are not programming languages; they are rendered or instruction-bearing assets that often influence trust, execution, and exploitability.

Use these modules when the target repo contains:
- markdown rendered to HTML or rich previews
- skill files, agent instructions, prompt templates, or tool manifests
- API specs, collections, or schema artifacts such as OpenAPI, Swagger, Postman, or GraphQL schema files
- notebooks with mixed code, markdown, output, and operational context
- documentation that may be treated as trusted operational input

---

## Module Map

| File | Focus |
|------|-------|
| `references/shared/artifacts/markdown.md` | markdown renderers, raw HTML, dangerous links, embeds, image fetches, and markdown-to-HTML trust boundaries |
| `references/shared/artifacts/skill-files.md` | `SKILL.md`, `AGENTS.md`, prompt templates, tool wrappers, instruction-precedence review, and operator-risk review for skill/agent repos |
| `references/shared/artifacts/api-specs.md` | OpenAPI, Swagger, Postman, GraphQL schema, hidden routes, auth drift, and leaked examples |
| `references/shared/artifacts/notebooks.md` | `.ipynb` notebooks, saved outputs, secrets, shell escapes, and operational leakage |

---

## Loading Guidance

- Load `markdown.md` when the repo renders markdown in web UIs, tickets, comments, wikis, docs previews, or email-like content.
- Load `skill-files.md` when the repo itself is a skill, agent, prompt, or LLM-integration target, when prompt templates and instruction files are first-class assets, or when setup flows and operator-facing commands are part of the artifact surface.
- Load `api-specs.md` when the repo ships OpenAPI, Swagger, Postman, Insomnia, AsyncAPI, or GraphQL schema artifacts.
- Load `notebooks.md` when `.ipynb` or similar mixed source/output notebook assets exist.
- Pair artifact review with `references/application/vulnerabilities/xss.md` when markdown or rich text reaches browsers.
- Pair artifact review with `references/application/vulnerabilities/ssrf.md` when markdown or embeds can fetch remote content.
- Pair artifact review with `references/application/vulnerabilities/prompt-injection.md` when the artifact carries instructions, retrieval content, or tool-call context.
- Pair artifact review with the existing dependency and data-exposure lenses when skill or agent repos direct global installs, secret access, or environment mutation through artifact content.
- Pair artifact review with `references/application/vulnerabilities/api-security.md`, `references/application/vulnerabilities/authorization.md`, and `references/application/vulnerabilities/sensitive-hardcoding.md` when specs, collections, or notebooks reveal hidden routes, auth drift, or embedded credentials.
