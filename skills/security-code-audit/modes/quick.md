# Quick Mode

Fast high-risk pass for immediate security signal.

---

## Scope

Prioritize Critical and High severity issues only. Do not attempt full category closure.

Use when:
- fast triage matters more than full coverage
- the repo is large and you need immediate signal
- you want likely-exploitable issues first

Report style is independent from quick-mode scan depth:
- `governance` keeps the brief report root-cause-first
- `exploit-first` makes attacker capability more visible
- `both` emits both concrete styles after one quick scan

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
- `references/shared/reporting/history-standard.md` if `.security-code-audit-reports/` history exists

---

## Recon Depth

Required:
- detect language and framework
- inventory code, templates, and obvious config files

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

At minimum, scan for:
- secrets and hardcoded sensitive values
- critical injection sinks or equivalent high-risk native surfaces for the active domain
- hardcoded credentials
- obvious dependency CVE exposure, including a native dependency audit command when the ecosystem tool is available
- debug mode, exposed diagnostics, and other clear RCE paths in application-style repos

If the active profile is `smart-contract`, triage privilege, external-call, accounting, signature, proxy, and deployment risk first rather than narrating a web-style Top 10 sweep.
Use `references/smart-contract/index.md` as the main router in that case.

If the active profile is `artifact-centric`, triage prompt, rendering, trust-boundary, secret, and environment risk first.

If one high-risk pattern is found, search for all occurrences of the same pattern before reporting.

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

Quick mode may keep the report compact, but it must still honor governance vs exploit-first presentation rules and must still record the concrete `Report Style` in report metadata.

Critical and High findings still require evidence and concrete PoC when feasible.

---

## Termination Criteria

Quick mode is complete when:
- all high-risk patterns in scope have been checked
- dependency audit tooling was run for detected ecosystems when feasible, or a limitation was recorded
- obvious Critical/High findings are documented
- repeated high-risk instances have been enumerated
- report output is generated
