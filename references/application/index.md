# Application Security Domain

Use this domain for traditional web, API, service, and mixed full-stack repos.

This domain keeps the audit centered on:
- auth, authz, input handling, data exposure, config, and trust boundaries
- API-specific drift, object-level access, and serializer/binding issues
- rendered content, prompt-bearing artifacts, dependency risk, and operational surfaces where they support an application audit

---

## Primary Entry Points

- `references/application/languages/index.md`
  Language-specific grep starters and dangerous sink reminders for application repositories.

- `references/application/vulnerabilities/index.md`
  Main category map for application security methodology.

- `references/application/frameworks/index.md`
  Framework-specific behavior and sink guidance.

- `references/shared/artifacts/index.md`
  Markdown, prompt, API-spec, notebook, and other artifact surfaces that can influence an application audit.

- `references/shared/dependencies/index.md`
  Ecosystem-specific dependency and supply-chain review.

- `references/application/exploits/index.md`
  Confirmation playbooks when a finding is verified or strongly suspected.

---

## When This Domain Is Primary

Use `application` as the active knowledge domain when:
- the repo is mainly web, API, backend, or full-stack code
- traditional request, session, template, database, file, or background-job surfaces dominate
- artifact review is supporting an application audit instead of being the target itself

This domain remains primary for the `artifact-centric` profile as well, but artifact modules should then dominate the actual scan order.

---

## Loading Guidance

1. Start with `references/application/vulnerabilities/index.md`.
2. Load only the language, framework, artifact, dependency, and specialist modules that match the observed surface.
3. Use `references/application/exploits/index.md` only when safe confirmation guidance is needed.
4. Keep contract-specific modules out unless the repo truly contains on-chain logic as a primary target.

---

## Boundary

This directory is a domain router, not a duplicate knowledge tree.

- Application-specific methodology still lives in `references/application/languages/`, `references/application/vulnerabilities/`, `references/application/frameworks/`, `references/shared/artifacts/`, `references/shared/dependencies/`, and `references/application/exploits/`.
- Smart-contract-specific methodology lives in `references/smart-contract/`.
