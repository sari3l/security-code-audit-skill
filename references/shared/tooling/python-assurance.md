# Optional Python Assurance

Use this module when the bundled Python assurance tools are available and the audit would benefit from deterministic seeding, structure checks, or report gates.

These tools are optional validators and candidate extractors. They are not the audit brain, not a closed static-analysis engine, and not proof that a target is safe.

---

## Boundary

The Python assurance layer may:
- seed raw observations and candidate capability records from instruction-bearing artifacts
- validate capability-map record shape, enums, references, and claim/effect contradictions
- validate audit-state ledger shape, freshness fields, and coverage count reconciliation
- validate report maturity gates such as candidate signals staying out of confirmed findings
- seed dangerous execution, shell code-loading, signing-material, and signed-state-consumer occurrences for manual reconciliation

The Python assurance layer must not:
- execute audited repository code, hooks, installers, package scripts, or tool wrappers
- fetch URLs declared by the audited repository
- suppress an LLM or human finding because no normalized capability record exists
- turn absence of candidates into a safety claim
- force every finding into the capability-map schema

---

## Open-World Rules

- Preserve raw observations before normalization.
- Put unknown but high-signal records into `unmapped-signals.jsonl` or `evidence-observations.jsonl` with `schema_gap`, `unstructured_hypothesis`, or `custom:*` labels.
- Treat checker failures as blockers for completeness claims, not as finding dismissal.
- Treat tool output as pre-promotion evidence. Apply `core/findings.md` and `references/shared/reporting/evidence-standard.md` before promoting anything to `Confirmed`.
- If a tool is unavailable, crashes, or does not support the current target, record `external_validator_unavailable`, `blocked`, or `manual_fallback` in `tool-invocations.jsonl`; continue with skill-native review.
- LLM or human reviewers may report risks outside the capability map when current evidence satisfies the evidence standard. Record why the schema was insufficient when material.

---

## Bundled Tools

The bundled tools live under `tools/` and use only the Python standard library.

| Tool | Purpose | Typical Output |
|------|---------|----------------|
| `tools/capability_map_seed.py` | Read instruction-bearing files and seed raw observations plus advisory capability candidates | `raw-observations.jsonl`, `unmapped-signals.jsonl`, `capabilities.jsonl`, `capability-paths.jsonl`, `capability-claims.jsonl` |
| `tools/capability_map_check.py` | Validate capability-map shape, enums, evidence refs, and claim/effect contradictions | JSON diagnostics with stable `CAP*` codes |
| `tools/audit_state_check.py` | Validate mandatory state files, freshness, and coverage count reconciliation | JSON diagnostics with stable `STATE*` codes |
| `tools/dangerous_capability_seed.py` | Seed open-world dangerous capability occurrences without executing audited code | JSON diagnostics or optional raw JSONL requiring manual state enrichment |
| `tools/report_render.py` | Render canonical `finding.v1` JSONL records into deterministic Markdown confirmed findings, including fenced PoC/evidence blocks, required evidence chains, and generated Mermaid attack flow | Markdown report or section plus `RENDER*` diagnostics |
| `tools/report_gate_check.py` | Validate report maturity boundaries, open observation routing, and optional dangerous-capability report reconciliation with `--run-dir` | JSON diagnostics with stable `REPORT*` codes |
| `tools/vulnerability_benchmark.py` | Evaluate benchmark reports for confirmed recall, signal preservation, false positives, false suppression, and coverage honesty | JSON metrics with stable `BENCH*` diagnostics plus report-gate diagnostics |

Use command resolution before invoking these tools. Resolve them from this skill directory, not from similarly named files inside the audited repository.

## Benchmarking

Use `tools/vulnerability_benchmark.py` for skill regression checks, prompt comparisons, and release confidence. It evaluates report behavior against curated cases:
- expected confirmed findings were reported with required evidence anchors
- high-signal unknowns were preserved as candidates, schema gaps, coverage debt, negative evidence, or optimization suggestions
- benign or negative-evidence cases were not promoted to confirmed findings
- complete coverage was not claimed while benchmark-required gaps remain

Benchmark cases are guardrails, not a closed vulnerability oracle. Passing the benchmark does not prove the skill is complete, and missing benchmark labels must not suppress current-code observations. Add cases that exercise unfamiliar shapes, negative examples, and coverage honesty whenever the skill changes in a way that could affect recall or false positives.

The release benchmark must contain labeled expectations for `dynamic_code_evaluation`, `shell_command_execution`, `shell_code_loading`, `signing_material`, and `signed_state_consumer`. Each sentinel family requires 100% recall independently; an empty fixture suite or a missing sentinel family fails instead of receiving a vacuous perfect score.
Each sentinel expectation must also define `record_ref`, `location`, `source`, `sink`, and `trace`; all anchors and expected terms must occur in the same Markdown finding/alert block. Whole-report keyword presence is insufficient.

---

## Failure Semantics

Stable code families:
- `CAP*`: capability-map structure, enum, evidence, and contradiction checks
- `SIG*`: preserved signal or unmapped-signal checks
- `STATE*`: audit-state lifecycle, freshness, and coverage checks
- `DANGER*`: dangerous-capability census, disposition, evidence, and count reconciliation
- `SEED*`: dangerous-capability seed target/input failures; these prevent a census claim
- `REPORT*`: report maturity and routing checks
- `BENCH*`: benchmark recall, false-positive, false-suppression, and coverage-honesty checks

Any failing validator means only that the checked artifact cannot support the corresponding claim. It does not mean the target is safe or unsafe by itself.

Examples:
- `CAP003` unknown effect enum: preserve the record as `schema_gap` or update the map; do not drop the source observation.
- `STATE020` coverage counts do not reconcile: withhold complete coverage and create coverage debt.
- `REPORT010` candidate in Findings: move it to Candidate Signals or add missing evidence before confirming.
- `REPORT030` missing canonical finding field: render from `output/security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}-findings.jsonl` or add the missing schema-backed Markdown field.
- `REPORT032` unstable display ID: sort canonical findings by severity rank, category/surface, and fingerprint, then number within severity.

---

## Recording Results

When a Python assurance tool is run:
- record the command and status in `tool-invocations.jsonl`
- store compact tool-output summaries in `evidence-observations.jsonl` when material
- write blockers or failed gates into `quality-gates.json`
- carry unresolved failures into coverage debt or report-visible limitations

Do not store large raw scanner output or whole source excerpts in state.
