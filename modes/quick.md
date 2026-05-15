# Quick Mode

Fast high-risk pass for immediate security signal.

---

## Scope

Prioritize Critical and High severity issues only. Do not attempt full category closure.

Quick mode is an `incremental-first` high-risk validation pass, not a history-first scan and not a remediation-retest mode.
Use current diffs plus audit-state indexes after freshness classification to select scope when that comparison is reliable, but do not let prior reports or prior state suppress current findings.
Audit state may provide indexed hints and prior knowledge for orientation; missing facts never prove a surface safe.
Prior coverage records can influence recheck priority only after freshness classification; they never mark unchanged surfaces safe.
Project context such as business assets, invariants, and trust-boundary claims may focus changed or invalidated high-risk surfaces, but quick mode does not build a full business model or full trust-boundary map.

`incremental-first` means:
- use change detection to decide which files and shared surfaces enter quick scope
- once a file or surface enters scope, review that file or surface as a normal quick-pass target rather than only reading the changed hunks
- always keep the cheapest global high-risk checks for secrets, hardcoded credentials, and manifest / lockfile dependency exposure

Do not inspect prior report details until the current quick-pass findings, coverage notes, and audit-state updates are complete.

Use when:
- fast triage matters more than full coverage
- the repo is large and you need immediate signal
- you want likely-exploitable issues first

---

## Required Load

- `references/application/languages/index.md`
- the active knowledge domain router after recon:
  - `references/application/index.md`
  - `references/smart-contract/index.md`
- relevant framework module only if it is immediately obvious and helps with high-risk checks
- `references/shared/dependencies/index.md` when lock files, manifests, vendored dependencies, or SCA artifacts are present
- `references/application/vulnerabilities/file-upload-download.md` when upload, download, export, archive, or object-storage surface exists
- `references/application/vulnerabilities/sensitive-hardcoding.md` when secrets or hardcoded sensitive values are plausible
- `references/shared/reporting/index.md`
- `references/shared/reporting/history-standard.md` if `.security-code-audit-reports/` history exists, but defer it until after the current-code quick pass is complete

---

## Recon Depth

Required:
- detect language and framework
- inventory code, templates, and obvious config files
- detect whether git metadata exists and whether the current working tree is clean
- perform audit state minimal probe only: latest/index/latest manifest/latest capsule/project profile
- build `current-change-context.json` from fresh current recon before loading prior state shards
- classify changed files and whether they hit critical shared surfaces before stage `3/6` when feasible

Not required:
- exhaustive route mapping
- full API version parity analysis
- full business-logic model
- full trust-boundary map

---

## Progress Labels

Quick mode still uses the shared 6-step progress display from `SKILL.md`, but stages `3/6` to `5/6` now come from the active target profile:

- `profiles/application.md`
- `profiles/smart-contract.md`
- `profiles/artifact-centric.md`

These labels should replace the neutral placeholder labels only after recon, before stage `3/6` starts.

---

## Scan Tasks

### Incremental Scope Selection

Use `incremental-first` scope selection whenever possible, but only after `current-change-context.json` exists.

For git-backed repos:
- collect committed delta from the latest usable state manifest snapshot to current `HEAD` only when that snapshot is a valid ancestor of `HEAD`
- collect local delta from current `HEAD` to the working tree, including staged, unstaged, and untracked files
- union committed delta and local delta, then fan out through `indexes/file-index.jsonl`, `indexes/route-index.jsonl`, `indexes/source-sink-index.jsonl`, `indexes/dependency-index.jsonl`, and `indexes/trust-boundary-index.jsonl`

For non-git repos:
- compare the current audit-relevant inventory against `indexes/file-index.jsonl` and the latest manifest snapshot identity
- use current inventory limitations and `current-change-context.json` to decide whether dynamic, generated, reflected, framework-magic, or artifact-mediated behavior makes the incremental baseline unreliable
- if state indexes are missing, stale, legacy-only, or structurally incomparable, ask the user whether to expand to full quick scope before continuing

Selective prior-state loading rules:
- first load only the latest capsule, current-change-context, and relevant index rows
- load old traces, function chains, deep gates, proof obligations, or knowledge records only when their ids are selected by changed surfaces, open obligations, unresolved hypotheses, remediation memory, or periodic high-risk review
- every reused record must receive a freshness status before it affects scope
- invalidated records can create quick tasks or coverage debt, but cannot mark a surface safe

Final quick scope is the union of:
- changed files
- changed or invalidated shared surfaces
- open proof obligations or historical high-risk chains selected by state indexes and knowledge
- cheap global checks for secrets, hardcoded credentials, and manifest / lockfile dependency risk

Do not reduce scope to patch hunks only. Once a file or surface is in scope, scan the relevant high-risk patterns across that full file or surface.

Ask the user whether to expand to full quick scope when any of these is true:
- no reliable baseline exists
- non-git diffing cannot produce a trustworthy audit-relevant delta
- a critical shared surface changed

Do not silently upgrade quick mode to `standard`. Recommend `standard` only when the user asks for full discovery or when the change blast radius is effectively repo-wide and a quick result would be misleading.

If the user declines expansion, continue in `strict incremental` mode and say explicitly that the result covers only change-impacted quick scope rather than a full quick audit of the current repo.
Carry unresolved high-signal observations as `evidence-observations.jsonl` records and route them before reporting, even when strict incremental mode keeps the report compact.

Critical shared surfaces include:
- auth, authz, session, and permission middleware
- shared input parsing, serialization, template rendering, and upload / download helpers
- dependency manifests, lockfiles, runtime security config, routers, entry points, gateway / proxy layers, and IaC
- smart-contract shared control surfaces such as privilege, proxy, deployment, accounting, signature, oracle, and cross-contract trust boundaries

State writes required in quick:
- `current-change-context.json` with changed files, changed shared surfaces, invalidations, and selective-load decisions
- `task-ledger.jsonl` for selected quick-scope work and expansion decisions
- `coverage-ledger.jsonl` with counted quick-scope coverage, even when not exhaustive
- `evidence-observations.jsonl` for high-signal observations, blockers, scanner gaps, and schema gaps
- `function-chains.jsonl` or explicit coverage debt for security-relevant functions in quick scope
- `quality-gates.json` before reporting

### Performance Guardrails

- prefer git diff over whole-tree hashing whenever git metadata is available
- hash only audit-relevant files for non-git or tree-based comparison; do not hash the entire repo
- keep non-git comparison data as a flat `file_inventory` plus one `aggregate_hash`; do not require a directory-level Merkle tree for the initial contract
- if diff fan-out becomes effectively repo-wide, stop pretending the run is still cheap and ask before expanding to full quick scope

At minimum, scan for:
- secrets and hardcoded sensitive values
- critical injection sinks or equivalent high-risk native surfaces for the active domain
- hardcoded credentials
- obvious dependency CVE exposure, including a native dependency audit command when the ecosystem tool is available
- debug mode, exposed diagnostics, and other clear RCE paths in application-style repos

If the active profile is `smart-contract`, triage privilege, external-call, accounting, signature, proxy, and deployment risk first rather than narrating a web-style Top 10 sweep.
Use `references/smart-contract/index.md` as the main router in that case.

If the active profile is `artifact-centric`, triage prompt, rendering, trust-boundary, secret, and environment risk first.

If one high-risk pattern is found, search for all materially affected occurrences across the current quick scope before reporting. If the root cause is a changed shared helper or sink family, widen locally enough to cover the affected scope before reporting.

After the current-code quick pass is complete, perform a deferred history replay:
- read up to 3 recent reports
- run the historical-miss gate first by reopening prior finding fingerprints against current code
- if a still-live prior vulnerability was missed, record the miss, emit `Skill Optimization Suggestions`, and withhold lifecycle finalization
- only when no historical misses exist may the report finalize `New`, `Recurring`, `Regression`, or `Fixed since last scan`

---

## May Skip

- full C1-C12 category sweep
- full coverage verification matrix
- basic attack-chain analysis beyond obvious chaining
- business-logic review
- race-condition review

---

## Output

- terminal summary
- brief history file in `.security-code-audit-reports/`

Quick mode may keep the report compact, but it must still preserve exploitability, evidence, remediation, coverage debt, and historical comparison when material.
It must also preserve material evidence observations, tool-output blockers, negative evidence, and schema gaps when they affect current quick-scope confidence.

Critical and High findings still require evidence and concrete PoC when feasible.

---

## Termination Criteria

Quick mode is complete when:
- all high-risk patterns in scope have been checked
- all cheap global checks have been checked
- dependency audit tooling was run for detected ecosystems when feasible, or a limitation was recorded
- obvious Critical/High findings are documented
- repeated high-risk instances have been enumerated
- any `strict incremental` limitation or expansion refusal is recorded when applicable
- material evidence observations are routed to confirmed findings, candidate signals, negative evidence, coverage debt, working hypotheses, or schema-gap suggestions
- audit state quality gates pass or the report explicitly states partial/blocked quick coverage
- report output is generated
