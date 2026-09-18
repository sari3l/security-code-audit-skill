# Shared Reference Modules

Use this directory for modules that are shared across the `application` and `smart-contract` knowledge domains.

These files are not a third audit domain. They are supporting layers that can be loaded from either domain when the observed surface requires them.

---

## Shared Areas

- `references/shared/audit-artifact-initialization.md`
  Shared ignore and directory-bootstrap rules for `output/` reports, canonical findings JSONL, and standardized state bundles.

- `references/shared/artifacts/index.md`
  Rendered, instruction-bearing, or analyst-authored assets such as markdown, prompt files, API specs, and notebooks.

- `references/shared/dependencies/index.md`
  Ecosystem-specific dependency review, native audit tooling, and future SCA integration guidance.

- `references/shared/tooling/command-resolution.md`
  Shared command-resolution standard for optional external scanners and repo-defined audit commands.

- `references/shared/tooling/python-assurance.md`
  Optional stdlib Python assurance helpers for signal-preserving candidate seeding, structure checks, audit-state checks, report gates, and benchmark report evaluation.

- `references/shared/state-standard.md`
  Mandatory machine-readable audit-state storage, advisory code fact snapshots, flexible evidence observations, trace-checkpoint persistence, function-chain inventory, and re-audit guidance for every scan.

- `references/shared/reporting/index.md`
  Findings, severity, remediation, coverage, history, and reporting standards.

---

## When To Load Shared Modules

- load `artifacts/` when the repo contains markdown renderers, prompt files, `SKILL.md`, `AGENTS.md`, notebooks, API specs, or other non-code assets that still affect trust or attack surface
- load `dependencies/` when manifests, lock files, vendored packages, images, SBOMs, or SCA output exist
- load `tooling/command-resolution.md` before invoking optional external scanners, repo-configured audit scripts, ecosystem audit commands, IaC scanners, secret scanners, smart-contract tools, SBOM tools, CI scanner wrappers, or bundled Python assurance tools
- load `tooling/python-assurance.md` when using the bundled optional Python validators or when a validator result must be interpreted without suppressing unmodeled LLM/human evidence
- load `audit-artifact-initialization.md` immediately before first creating the running directory's `output/` artifact root, report, canonical findings JSONL, or standardized state bundle
- load `state-standard.md` for every run; large, long-running, beta `multi`, or state-worthy smart-contract scans should preserve richer detail, but even compact runs should preserve advisory code facts and high-signal evidence observations
- load `reporting/` near coverage verification, history comparison, severity calibration, and final report generation

Tracing methodology itself lives in `core/bidirectional-tracing.md`, not in `shared/`.

---

## Boundary

- `shared/` supports both domains
- `application/` remains the primary knowledge corpus for web, API, backend, and artifact-centric audits
- `smart-contract/` remains the primary knowledge corpus for Solidity and on-chain logic
