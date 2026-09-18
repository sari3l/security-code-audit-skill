# Audit Artifact Directory Initialization

Use this shared flow immediately before creating the report `output/` directory or any scan-generated artifact below it.

Its job is to keep audit artifacts out of repo history and local tool indexes without forcing extra tool-specific config files into someone else's project.

---

## Managed Directories

Always treat this as the managed artifact root:
- `output/`

Reports, canonical finding JSONL, and run-state bundles all live below `output/` with the `security-code-audit-` prefix.

---

## Invocation Rules

- run this flow only when the managed artifact root is about to be created
- call it before first creating `output/`
- do not use this flow as a reason to eagerly create report, findings, or state artifacts
- after the flow completes, create only the file or directory the current path actually needs

This keeps `reports` and `state` aligned without changing their separate creation timing rules.

---

## Ignore Policy

1. Detect whether the running directory has git metadata.
   - treat a `.git` directory or `.git` file as git metadata
2. If git metadata exists:
   - ensure `.gitignore` contains `output/`
   - create `.gitignore` if it does not already exist
3. If git metadata does not exist:
   - do not create or edit `.gitignore`
4. For each optional existing ignore file in the running directory, ensure it contains both managed-directory entries:
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
- `output/`

---

## Handoff Back To Callers

After ignore maintenance:
- the report path may create `output/` immediately if it is needed
- the state path may create `output/security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}-state/` only when the first state file is ready to write
- the state path must still obey the non-empty-directory rule from `references/shared/state-standard.md`

---

## Why This Exists

- prevent accidental commit or sharing of audit artifacts from third-party repos
- keep report and state initialization behavior from drifting apart
- avoid injecting this skill's tool preferences into repos that do not already use those tool-specific ignore files
