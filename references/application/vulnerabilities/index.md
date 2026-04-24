# Core Vulnerability Modules

This directory contains principle- and methodology-focused vulnerability references. These files answer:

- what the weakness is
- where it usually appears in code and architecture
- how to audit for it systematically
- what safe patterns look like

Exploit reproduction and payload-heavy confirmation flows live in `references/application/exploits/`.
Treat public POCs and sample payloads as examples only. The real audit target is the parser, normalizer, serializer, router, policy, or state logic that makes those probes work.

---

## Core Modules

These map to the framework's main audit categories C1-C12.

| Category | File | Focus |
|----------|------|-------|
| C1 | `references/application/vulnerabilities/injection.md` | cross-sink injection overview, sink triage, routing to deeper modules |
| C2 | `references/application/vulnerabilities/authentication.md` | sessions, JWT, reset flows, MFA, brute-force resistance |
| C3 | `references/application/vulnerabilities/authorization.md` | IDOR/BOLA, vertical and horizontal privilege escalation, tenancy boundaries |
| C4 | `references/application/vulnerabilities/mass-assignment.md` | unsafe object binding, serializer overreach, nested writes |
| C5 | `references/application/vulnerabilities/data-exposure.md` | secrets, PII, stack traces, debug data, export leakage |
| C6 | `references/application/vulnerabilities/security-misconfiguration.md` | insecure defaults, debug mode, CORS, cookie/header mistakes |
| C7 | `references/application/vulnerabilities/xss.md` | reflected, stored, DOM XSS, output contexts, sanitization failures |
| C8 | `references/shared/dependencies/index.md` | ecosystem-specific dependency audit routing, transitive risk, native tooling, future SCA inputs |
| C9 | `references/application/vulnerabilities/cryptography.md` | weak hashing, RNG, key handling, token signing, TLS mistakes |
| C10 | `references/application/vulnerabilities/ssrf.md` | outbound request abuse, metadata reachability, redirect and DNS tricks |
| C11 | `references/application/vulnerabilities/logging-monitoring.md` | secret-safe logging, audit trails, log injection, alerting, and log access control |
| C12 | `references/application/vulnerabilities/infrastructure.md` | Docker, k8s, Helm, Terraform, IAM, network exposure, and secret handling in IaC |

---

## OWASP Top 10 Coverage Notes

This core set is organized by the audit framework's categories rather than copying OWASP names verbatim, but it covers the same main surface:

- `authorization.md` maps strongly to Broken Access Control
- `cryptography.md` and `data-exposure.md` cover Cryptographic Failures
- `injection.md` and `xss.md` cover Injection-class issues
- `security-misconfiguration.md` covers Security Misconfiguration
- `references/shared/dependencies/index.md` covers Vulnerable and Outdated Components through a dedicated ecosystem-specific workflow
- `authentication.md` covers Identification and Authentication Failures
- `business-logic.md` and `api-security.md` help cover Insecure Design and API-specific trust mistakes
- `ssrf.md` covers SSRF directly
- `logging-monitoring.md` and `infrastructure.md` cover operational surfaces that often decide whether app-layer issues become detectable or exploitable

For audits that want explicit OWASP language in reporting, use these modules as the implementation layer and map findings back to the OWASP category in the final report.

---

## Specialist Modules

These are deeper topical references that complement the core set.

| File | Purpose |
|------|---------|
| `references/application/vulnerabilities/sql-injection.md` | deep SQLi coverage: value, identifier, clause, ORM, second-order cases |
| `references/application/vulnerabilities/command-injection.md` | shell, argument, option, and wrapper-based command execution abuse |
| `references/application/vulnerabilities/deserialization.md` | unsafe object materialization, gadget paths, signed-state misuse |
| `references/application/vulnerabilities/api-security.md` | API-specific object, property, flow, and cross-version security issues |
| `references/application/vulnerabilities/business-logic.md` | router for stateful workflow flaws and invariant-driven review |
| `references/application/vulnerabilities/pricing-and-accounting.md` | negative values, client-controlled amounts, rounding, and settlement abuse |
| `references/application/vulnerabilities/state-machine-abuse.md` | invalid transitions, skipped prerequisites, and terminal-state violations |
| `references/application/vulnerabilities/limits-and-quotas.md` | quota, cap, count, plan, and free-tier abuse |
| `references/application/vulnerabilities/workflow-replay.md` | replay, reuse, idempotency, and one-time-step failures |
| `references/application/vulnerabilities/file-upload-download.md` | upload, download, replace, object-key, filename, size, archive, and tokenized file access issues |
| `references/application/vulnerabilities/path-traversal.md` | path joins, absolute-path abuse, parser differentials, Zip Slip, normalization, and prefix escape |
| `references/application/vulnerabilities/configuration-files.md` | `.env`, container, proxy, CI, and deployment config review |
| `references/application/vulnerabilities/sensitive-hardcoding.md` | hardcoded tokens, cloud keys, credentials, connection strings, and internal topology |
| `references/application/vulnerabilities/race-conditions.md` | concurrency, TOCTOU, multi-request state corruption |
| `references/application/vulnerabilities/xss-templates.md` | template-engine-specific escaping bypasses |
| `references/application/vulnerabilities/prompt-injection.md` | prompt-boundary failures, repo-instruction drift, tool-call steering |
| `references/smart-contract/vulnerabilities/smart-contracts.md` | compact overview that routes into the dedicated smart-contract domain |

---

## Loading Guidance

- Load the relevant core modules for every standard or deep audit.
- Pull in specialist modules when the project surface matches them.
- For C1, start with `references/application/vulnerabilities/injection.md` and then load the specific sink-family modules that match the codebase.
- For C8, route to `references/shared/dependencies/index.md` and load the ecosystem modules that match the repo's manifests and lock files.
- For C11, load `references/application/vulnerabilities/logging-monitoring.md` whenever the repo logs auth, errors, admin actions, exports, or security events.
- For upload, download, export, archive extraction, or object storage flows, load `references/application/vulnerabilities/file-upload-download.md`.
- For dynamic path composition, file viewers, archive extraction, filesystem/object-key escape risk, or proxy/framework path parsing drift, also load `references/application/vulnerabilities/path-traversal.md`.
- For C5, include `references/application/vulnerabilities/sensitive-hardcoding.md` when scanning source, config, CI, examples, or generated artifacts for embedded secrets and topology.
- For C6 and C12, include `references/application/vulnerabilities/configuration-files.md` whenever repo-tracked config or deployment files exist, and load `references/application/vulnerabilities/infrastructure.md` for IaC-specific trust and exposure review.
- For AI, prompt, repo-doc, or instruction-bearing surfaces, include `references/application/vulnerabilities/prompt-injection.md`.
- For business-state surfaces, start with `references/application/vulnerabilities/business-logic.md`, then route immediately into pricing/accounting, state-machine, limits/quotas, workflow-replay, and race-condition modules that match the observed invariant.
- For `.sol` contracts, Foundry, Hardhat, or proxy/oracle/signature-heavy on-chain logic, switch primary routing to `references/smart-contract/index.md` and use `references/smart-contract/vulnerabilities/smart-contracts.md` as the compact overview.
- Use `references/application/exploits/index.md` only after a vulnerability is verified or strongly suspected and you need confirmation guidance.
