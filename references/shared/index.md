# Shared Reference Modules

Use this directory for modules that are shared across the `application` and `smart-contract` knowledge domains.

These files are not a third audit domain. They are supporting layers that can be loaded from either domain when the observed surface requires them.

---

## Shared Areas

- `references/shared/audit-artifact-initialization.md`
  Shared ignore and directory-bootstrap rules for `.security-code-audit-reports/` and `.security-code-audit-state/`.

- `references/shared/artifacts/index.md`
  Rendered, instruction-bearing, or analyst-authored assets such as markdown, prompt files, API specs, and notebooks.

- `references/shared/dependencies/index.md`
  Ecosystem-specific dependency review, native audit tooling, and future SCA integration guidance.

- `references/shared/state-standard.md`
  Mandatory machine-readable audit-state storage, trace-checkpoint persistence, function-chain inventory, and re-audit guidance for every scan.

- `references/shared/reporting/index.md`
  Findings, severity, remediation, coverage, history, and reporting standards.

---

## When To Load Shared Modules

- load `artifacts/` when the repo contains markdown renderers, prompt files, `SKILL.md`, `AGENTS.md`, notebooks, API specs, or other non-code assets that still affect trust or attack surface
- load `dependencies/` when manifests, lock files, vendored packages, images, SBOMs, or SCA output exist
- load `audit-artifact-initialization.md` immediately before first creating `.security-code-audit-reports/` or `.security-code-audit-state/`
- load `state-standard.md` for every run; large, long-running, beta `multi`, or state-worthy smart-contract scans should preserve richer detail
- load `reporting/` near coverage verification, history comparison, severity calibration, and final report generation

Tracing methodology itself lives in `core/bidirectional-tracing.md`, not in `shared/`.

---

## Boundary

- `shared/` supports both domains
- `application/` remains the primary knowledge corpus for web, API, backend, and artifact-centric audits
- `smart-contract/` remains the primary knowledge corpus for Solidity and on-chain logic
