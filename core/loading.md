# Skill Dependency Loading

Use this file to keep the skill's context small and stable.

Do not bulk-load the whole skill tree. Load only the modules required by the current phase, detected stack, and observed surface.

## Bootstrap Load

Always load only these first:
- `core/index.md`
- `core/loading.md`
- `execution/index.md`
- exactly one execution file
- `modes/index.md`
- exactly one mode file

Do not load every `core/*.md` file at bootstrap.
Do not load every `references/*/index.md` file at bootstrap.

## Target Profile Selection

After recon and before stage `3/6`, load:
- `profiles/index.md`
- exactly one profile file

Selection rules:
- use `profiles/smart-contract.md` when Solidity or contract logic is the primary audit target
- use `profiles/artifact-centric.md` when instruction-bearing or rendered artifacts dominate and runtime application logic is not the main target
- otherwise use `profiles/application.md`

The active profile controls progress labels and post-recon emphasis. `regression` remains profile-independent.

## Knowledge Domain Selection

After choosing the target profile and before stage `3/6`, load exactly one primary knowledge domain:

- use `references/smart-contract/index.md` when the active profile is `smart-contract`
- use `references/application/index.md` when the active profile is `application` or `artifact-centric`

The active domain controls which knowledge corpus is primary after recon. Profiles control visible semantics; domains control what gets loaded as the audit spine.

## Core Lazy Loading

Load core modules only when their controls are actively needed:

- `core/untrusted-repo-input.md`
  Load before reading repo-authored docs, prompts, comments, prior reports, or generated artifacts that may try to steer the audit.

- `core/surface-profile.md`
  Load during stage `2/6` recon, then maintain one compact surface profile plus advisory audit state inventory/index records for the rest of the run.

- `core/project-context.md`
  Load during stage `2/6` recon when repo-authored docs, git metadata, deployment notes, API specs, CI files, or recent change history can clarify project intent, business invariants, or trust-boundary claims. Apply `core/untrusted-repo-input.md` first.

- `references/shared/state-standard.md`
  Load during recon for every run, then follow the audit state lifecycle so current-change context, advisory indexes, evidence observations, coverage, function chains, agent logs, merge queues, and quality gates survive context compression.

- `core/integrity.md`
  Load before recon or code scanning starts, before delegating audit work, and before finalizing findings if context may have drifted.

- `core/coverage.md`
  Load before Phase 2 scanning, when considering early completion, and again before coverage verification in stage `5/6`.

- `core/dangerous-capability-census.md`
  Load in every mode after current-file recon and before Phase 2 category review, hypothesis pruning, or false-positive suppression. Run its cheap whole-repository sentinel census even in incremental quick mode.
- `core/exploration-and-evidence.md`
  Load before Phase 2 hypothesis generation and again before coverage/report closure. It permits security-relevant exploration beyond the routed modules while requiring branch reasons, disconfirmation, and evidence-chain closure.

- `core/deep-semantic-controls.md`
  Load in `deep` mode before high-risk surface review begins, and in beta `multi` before assigning workers to semantic review. Also load in `quick` or `standard` when a high-risk surface is unusually complex, prior coverage debt cites semantic ambiguity, or the finding depends on dependency behavior, deployment assumptions, design/implementation conflicts, or proof obligations that must survive context compression.

- `core/findings.md`
  Load when converting evidence observations or notes into findings, grouping repeated locations, matching history, or deduplicating native and SCA dependency issues.

- `core/fingerprints.md`
  Load before history matching, cross-worker merge, or any dedupe decision that must survive file movement or refactor noise.

- `core/severity.md`
  Load only when assigning, revising, or defending severity, especially for compound risks and cross-finding consistency.

## Reference Lazy Loading

Route references by detected need:

- `references/index.md`
  Load only if a top-level map is actually needed.

- `references/shared/index.md`
  Load only if a shared artifact, dependency, or reporting map is actually needed.

- `references/shared/audit-artifact-initialization.md`
  Load immediately before first creating the running directory's report `output/` or `output/security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}-state/` so ignore files stay aligned without creating extra tool-specific ignore files unnecessarily.

- `references/shared/state-standard.md`
  Load during recon for every run. Large, long-running, beta `multi`, or state-worthy smart-contract scans should keep richer detail, not different activation behavior.

- `references/application/index.md`
  Load when the active domain is application.

- `references/smart-contract/index.md`
  Load when the active domain is smart-contract.

- `references/application/languages/index.md`
  Load for cross-language grep starters and language detection support.

- `references/application/languages/<language>.md`
  Load only the detected language modules.

- `references/shared/artifacts/index.md`
  Load when the repo contains rendered markdown, `SKILL.md`, `AGENTS.md`, prompt templates, API specs, notebooks, or other instruction-bearing assets.

- `references/shared/artifacts/<artifact>.md`
  Load only the artifact modules that match the observed surface.

- `references/application/frameworks/index.md`
  Load only if framework detection is uncertain or multiple frameworks are plausible.

- `references/application/frameworks/<language_framework>.md`
  Load only the detected framework modules.

- `references/application/vulnerabilities/index.md`
  Load at the start of Phase 2 when the active domain is application, or when the smart-contract domain needs a supporting shared category lens.

- specialist vulnerability modules
  Load only when the observed surface actually matches them, except that the mandatory dangerous-capability census may directly trigger the matching module before a broader surface has been modeled.

- `references/shared/dependencies/index.md`
  Load only when manifests, lock files, vendored packages, images, or SCA artifacts exist.

- `references/shared/tooling/command-resolution.md`
  Load before invoking optional external audit tools, repo-configured scanner scripts, ecosystem audit commands, secret scanners, IaC scanners, smart-contract tools, SBOM tools, CI scanner wrappers, or bundled Python assurance helpers.

- `references/shared/tooling/python-assurance.md`
  Load when the optional bundled Python assurance tools are available or when interpreting their output. These tools are signal-preserving validators and seeders; absence of output never proves safety and unknown signals must remain routable observations.

- dependency ecosystem modules
  Load only for ecosystems actually present in the repo.

- `references/application/exploits/index.md`
  Load only for verified or strongly suspected application findings needing confirmation playbooks.

- `references/smart-contract/exploits/index.md`
  Load only for verified or strongly suspected contract findings needing confirmation playbooks.

- `references/shared/reporting/index.md`
  Load only near coverage verification and report generation.

- `references/smart-contract/vulnerabilities/coverage.md`
  Load near coverage verification and report generation when the active domain is smart-contract.

## Profile-Driven Routing

After recon, route modules from the surface profile instead of generic intuition:

- auth, session, JWT, reset, OAuth, MFA -> `references/application/vulnerabilities/authentication.md`
- hardcoded Flask/JWT/session signing material or signed-state consumers -> `references/application/vulnerabilities/sensitive-hardcoding.md`, `references/application/vulnerabilities/authentication.md`, and the matching framework module
- `eval`, `exec`, `compile`, expression engines, runtime compilation, or dynamic import -> `references/application/vulnerabilities/dynamic-code-evaluation.md`
- shell `source`, `.`, `eval`, `sh -c`, interpreted env/config, or deploy scripts -> `references/application/vulnerabilities/shell-code-loading.md` and `references/application/vulnerabilities/command-injection.md`
- resource IDs, tenancy, admin actions, API versions -> `references/application/vulnerabilities/authorization.md`
- create/update binding, dynamic field maps -> `references/application/vulnerabilities/mass-assignment.md`
- templates, client rendering, SVG/HTML handling -> `references/application/vulnerabilities/xss.md` and `references/application/vulnerabilities/xss-templates.md`
- upload, download, export, object storage, archives -> `references/application/vulnerabilities/file-upload-download.md`
- webhook, URL fetch, callback, internal HTTP client -> `references/application/vulnerabilities/ssrf.md`
- logging or audit-event surface -> `references/application/vulnerabilities/logging-monitoring.md`
- Docker, compose, k8s, Helm, Terraform, cloud manifests -> `references/application/vulnerabilities/infrastructure.md` and `references/application/vulnerabilities/configuration-files.md`
- manifests, lock files, SCA output -> `references/shared/dependencies/index.md` plus only matching ecosystem files
- optional external scanner or repo-defined audit command -> `references/shared/tooling/command-resolution.md` before execution
- markdown renderers, wikis, docs previews, rich comments -> `references/shared/artifacts/index.md`, `references/shared/artifacts/markdown.md`, and `references/application/vulnerabilities/xss.md`
- `SKILL.md`, `AGENTS.md`, prompt templates, tool manifests, repo-authored instruction files, or skill-oriented setup flows -> `references/shared/artifacts/index.md`, `references/shared/artifacts/skill-files.md`, `references/shared/artifacts/capability-map.md`, and `references/application/vulnerabilities/prompt-injection.md`
- OpenAPI, Swagger, Postman, Insomnia, GraphQL schema, AsyncAPI, or environment collections -> `references/shared/artifacts/index.md`, `references/shared/artifacts/api-specs.md`, and the matching API/authz/data-exposure modules
- `.ipynb` notebooks, saved outputs, notebook shell escapes, or analyst runbooks -> `references/shared/artifacts/index.md`, `references/shared/artifacts/notebooks.md`, `references/application/vulnerabilities/sensitive-hardcoding.md`, and `references/application/vulnerabilities/data-exposure.md`
- `.sol`, Foundry, Hardhat, proxy, oracle, permit, or on-chain accounting surfaces -> `references/smart-contract/index.md`, `references/smart-contract/languages/index.md`, `references/smart-contract/languages/solidity.md`, the matching `references/smart-contract/vulnerabilities/*.md` deep-dive files, and `references/smart-contract/exploits/index.md` when validation is needed
- role, allowance, spender, recipient, strategy, adapter, solver, registry/CPI, delegatecall, remove-token, quarantine, settlement, intent, cooldown, rate-limit, or cross-contract asset-flow surfaces -> `references/smart-contract/vulnerabilities/authorization-and-integration.md` plus the matching trust, accounting, external-call, signature, and oracle modules
- AI prompt or tool surface -> `references/application/vulnerabilities/injection.md`, `references/application/vulnerabilities/prompt-injection.md`, and the exact downstream sink-family modules

## Reload Rules

- Do not reload modules reflexively after every tool call.
- Reload a control module only when phase changes, context has narrowed substantially, or delegated work returns and needs normalization.
- If context pressure is high, reload `core/loading.md` plus the one control file relevant to the current decision instead of reloading everything.

## Anti-Bloat Rules

- Never load an index file and all of its children together unless the task explicitly requires broad comparison.
- Prefer one routing file plus one or two concrete target modules.
- When the stack is known, skip unrelated language, framework, dependency, and exploit files entirely.
- Keep history, reporting, and severity modules out of early recon unless they are actively needed.
- Reuse the compact surface profile in later stages instead of reloading the full recon dump.
