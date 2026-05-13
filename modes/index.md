# Mode Index

These files define execution scope. They are not part of `references/` because they control workflow depth rather than provide audit knowledge.

Execution topology lives separately in `../execution/`.
Target semantics live separately in `../profiles/`.
Primary knowledge routing lives in `../references/application/` and `../references/smart-contract/`.

Common rules remain in:
- `SKILL.md` for shared workflow, shared category definitions, and report template
- `core/` for integrity, coverage, finding, and severity controls
- `references/` for language, framework, vulnerability, exploit, and reporting knowledge

---

## Mode Selection

`help`, `-h`, and `--help` are not modes. They are handled as an early-exit help path in `SKILL.md`.

- `quick`
  Incremental-first high-risk validation using current diffs, reliable audit-state freshness, and global cheap checks. Use `quick.md`.

- `standard`
  Default full current-code discovery with structured coverage and practical business/trust-boundary review. Use `standard.md`.

- `deep`
  Semantic-assurance audit with stronger closure for invariants, trust boundaries, data lifecycle, attack chains, and proof obligations. Use `deep.md`.

- `regression`
  Latest-report remediation retest with early exit when no usable report exists. Use `regression.md`.

If no argument is provided, use `standard`.

Mode controls scope, depth, and stop conditions only:

| Mode | Primary purpose | Business / trust-boundary use |
|------|-----------------|-------------------------------|
| `quick` | Incremental high-risk validation | Use assets, invariants, and trust-boundary claims only to focus changed or invalidated high-risk surfaces. |
| `standard` | Full current-code discovery | Include business assets, invariants, and trust boundaries as practical discovery inputs. |
| `deep` | Semantic assurance | Close or explicitly debt-track material invariants, trust boundaries, data lifecycle, attack chains, and proof obligations. |
| `regression` | Latest-report retest | Reopen reported paths and their surrounding current-code surfaces only. |

Target profile still controls semantics after recon, knowledge domain still controls the primary reference spine, and execution mode still controls agent topology.

---

## Loading Guidance

1. Parse the first skill argument.
2. Load `core/index.md` and `core/loading.md`.
3. Load this file.
4. Load exactly one mode file:
   - `modes/quick.md`
   - `modes/standard.md`
   - `modes/deep.md`
   - `modes/regression.md`
5. Initialize the shared 6-step progress plan from `SKILL.md`, but keep stages `3/6` to `5/6` as neutral placeholders.
6. After recon, load `profiles/index.md` plus exactly one target profile file, then replace the placeholder labels for stages `3/6` to `5/6`.
7. Then use `core/loading.md` to select exactly one primary knowledge domain.
8. Then use `core/loading.md` to lazy-load the required controls and references for that mode.

---

## Progress Display

All modes use the same shared stage-based progress display from `SKILL.md`.

- Use `update_plan` for the canonical progress state.
- Every `update_plan` call must include the full six-stage list in stable numeric order from `[1/6]` through `[6/6]`.
- Do not reorder plan items when stage labels change or when a different stage becomes `in_progress`.
- Stages `1/6`, `2/6`, and `6/6` are shared across all modes.
- Before recon completes, stages `3/6`, `4/6`, and `5/6` must stay neutral placeholders.
- For `quick`, `standard`, and `deep`, stages `3/6`, `4/6`, and `5/6` must switch in place to the exact labels defined by the active target profile file only after recon selects that profile.
- `regression` keeps its own fixed labels from `modes/regression.md`.
- Use commentary only to add concrete subtask context; do not repeat the exact stage title already shown in the plan.
- Use ASCII bars only as a fallback when the host cannot render structured plan progress.
- Do not use fake percentages. The visible progress is approximate and phase-based.
- The difference between modes is usually the amount of work inside stages 3 to 5; `regression` may also exit early when no usable baseline report exists.

---

## Design Intent

- `SKILL.md` holds shared rules and shared structure.
- `core/` holds audit quality controls and the lazy-loading router that apply to every run.
- `modes/*.md` hold only mode-specific scope, required depth, and stop conditions.
- `profiles/*.md` hold target-specific semantics and progress wording after recon.
- `references/application/` and `references/smart-contract/` hold the post-recon knowledge spines.
- `references/` holds the reusable knowledge base.
