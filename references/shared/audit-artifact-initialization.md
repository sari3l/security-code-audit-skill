# Audit Artifact Directory Initialization

Use this shared flow immediately before creating `.security-code-audit-reports/` or `.security-code-audit-state/`.

Its job is to keep audit artifacts out of repo history and local tool indexes without forcing extra tool-specific config files into someone else's project.

---

## Managed Directories

Always treat these as one shared ignore set:
- `.security-code-audit-reports/`
- `.security-code-audit-state/`

If either directory is about to be created, ensure ignore coverage for both directories in the same pass.

---

## Invocation Rules

- run this flow only when one of the managed directories is about to be created
- call it before first creating `.security-code-audit-reports/`
- call it before first creating `.security-code-audit-state/`
- do not use this flow as a reason to eagerly create both directories
- after the flow completes, create only the directory the current path actually needs

This keeps `reports` and `state` aligned without changing their separate creation timing rules.

---

## Ignore Policy

1. Detect whether the project root has git metadata.
   - treat a `.git` directory or `.git` file as git metadata
2. If git metadata exists:
   - ensure `.gitignore` contains `.security-code-audit-reports/`
   - ensure `.gitignore` contains `.security-code-audit-state/`
   - create `.gitignore` if it does not already exist
3. If git metadata does not exist:
   - do not create or edit `.gitignore`
4. For each optional existing ignore file in the project root, ensure it contains both managed-directory entries:
   - `.claudeignore`
   - `.cursorignore`
   - `.ignore`
   - `.rgignore`
5. Do not create those optional tool-specific ignore files just for this skill.
6. Keep the write behavior idempotent:
   - append only missing entries
   - do not duplicate existing lines
   - preserve unrelated content

Use root-relative directory entries with trailing slashes:
- `.security-code-audit-reports/`
- `.security-code-audit-state/`

---

## Handoff Back To Callers

After ignore maintenance:
- the report path may create `.security-code-audit-reports/` immediately if it is needed
- the state path may create `.security-code-audit-state/` only when the first state file is ready to write
- the state path must still obey the non-empty-directory rule from `references/shared/state-standard.md`

---

## Why This Exists

- prevent accidental commit or sharing of audit artifacts from third-party repos
- keep report and state initialization behavior from drifting apart
- avoid injecting this skill's tool preferences into repos that do not already use those tool-specific ignore files
