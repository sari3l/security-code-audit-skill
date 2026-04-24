# Reference Index

This directory is the skill's reference library. Use it as the top-level navigation layer before loading deeper modules.

Execution strategy files live in `../modes/` and quality-control files live in `../core/`. They are intentionally not stored under `references/` because they control workflow quality and depth rather than provide audit knowledge.

## Sections

- `references/shared/index.md`
  Shared artifact, dependency, and reporting modules used by both application and smart-contract audits.

- `references/application/index.md`
  Traditional web, API, service, and mixed full-stack application security domain.

- `references/smart-contract/index.md`
  Contract-native knowledge domain for Solidity, accounting, signatures, upgradeability, and market abuse.

- `references/application/languages/index.md`
  Fast grep starters and language-specific dangerous sinks for the application domain.

- `references/application/frameworks/index.md`
  Framework-specific audit notes grouped by `language_framework`.

- `references/shared/artifacts/index.md`
  Markdown, prompt, skill, API-spec, notebook, and other instruction-bearing artifact review guidance.

- `references/application/vulnerabilities/index.md`
  Core vulnerability methodology and specialist deep-dive modules.

- `references/smart-contract/vulnerabilities/index.md`
  Contract-native methodology and deep dives for trust, accounting, signatures, oracle abuse, and upgradeability.

- `references/shared/dependencies/index.md`
  Ecosystem-specific dependency audit flows, native tooling choices, and future SCA integration guidance.

- `references/shared/audit-artifact-initialization.md`
  Shared ignore maintenance and directory-bootstrap rules for `.security-code-audit-reports/` and `.security-code-audit-state/`.

- `references/shared/state-standard.md`
  Mandatory audit-state storage, trace-checkpoint persistence, function-chain inventory, and change-aware re-audit guidance for every scan.

- `references/application/exploits/index.md`
  Application exploit verification playbooks and confirmation guidance.

- `references/smart-contract/exploits/index.md`
  Contract exploit verification playbooks and confirmation guidance.

- `references/shared/reporting/index.md`
  Report structure, PoC quality, remediation rules, severity, and coverage standards.

## Loading Guidance

- After recon, choose the primary knowledge domain:
  - `references/smart-contract/index.md` for Solidity or contract-heavy repos
  - `references/application/index.md` for everything else, including artifact-centric audits
- Shared support: load `references/shared/index.md` when the repo contains artifact surfaces, dependency surfaces, or reporting/history work is about to begin.
- Phase 1:
  - `application` audits should load `references/application/languages/index.md` and only the detected `references/application/frameworks/*.md` files
  - `smart-contract` audits should load `references/smart-contract/languages/index.md`
- Artifact surfaces: load `references/shared/artifacts/index.md` when the repo contains rendered markdown, `SKILL.md`, `AGENTS.md`, prompt templates, API specs, notebooks, or other instruction-bearing files.
- Audit artifact bootstrap: load `references/shared/audit-artifact-initialization.md` immediately before first creating `.security-code-audit-reports/` or `.security-code-audit-state/`.
- Scan-state continuity: load `references/shared/state-standard.md` for every run, then keep richer detail when the repo is large, long-running, beta `multi`, or state-worthy smart-contract.
- Phase 2: use the chosen domain as the main audit map, then pull the relevant shared artifact, dependency, and exploit modules.
- C8 and supply-chain review: load `references/shared/dependencies/index.md`, then the ecosystem files matching detected manifests and lock files. If external SCA output exists, also load `references/shared/dependencies/sca-integration.md`.
- Verification:
  - use `references/application/exploits/index.md` for application findings
  - use `references/smart-contract/exploits/index.md` for contract findings
- Phase 3 and Phase 4: load `references/shared/reporting/index.md` for coverage verification, severity calibration, report structure, and remediation standards.
