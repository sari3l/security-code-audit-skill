# Deep Semantic Controls

Use this control in `deep` mode and whenever a high-risk surface needs semantic review beyond pattern matching.

This file defines the durable state contract for deep audit reasoning. It does not replace surface-specific vulnerability modules. The core contract preserves facts, assumptions, conflicts, proof obligations, and coverage state; the specialist modules define the sensitive details that must be checked for each vulnerability family.

---

## Purpose

Deep semantic controls exist to prevent:
- context compression from flattening "reviewed this deeply" into an unsupported memory
- broad abstractions from erasing vulnerability-specific edge cases
- worker-local reasoning from disappearing before supervisor merge
- design, dependency, deployment, and implementation conflicts from being treated as incidental notes
- incomplete high-risk review from being reported as covered

They do not exist to:
- store large code excerpts or scanner output
- replace fresh code reading
- collapse all vulnerability families into one generic checklist
- prove a surface safe because a previous checkpoint exists

---

## Activation

Always load this control for:
- `deep` mode
- beta `multi` execution when any worker owns high-risk review
- smart-contract oracle, accounting, signature, upgrade, proxy, callback, or multi-contract trust surfaces
- application authz, SQLi, SSRF, file lifecycle, XSS, deserialization, business logic, race, dependency, IaC, or deployment-sensitive surfaces when they materially affect exploitability

For `quick` and `standard`, use this control only when a surface is unusually complex or when a prior run produced coverage debt tied to semantic ambiguity.

---

## Durable Typed Blackboard

Deep semantic state is a durable typed blackboard stored in `.security-code-audit-state/`.

It must be persisted incrementally, not reconstructed only at report time. In large projects, a gate that exists only in the agent's working memory should be treated as not yet durable.

Record compact facts and references:
- file paths and line numbers
- function, route, contract, helper, parser, adapter, or dependency names
- dependency versions and relevant documented semantics
- checked assumptions and verification result
- unresolved proof obligations
- negative evidence and blockers
- evidence observation refs for raw observations, tool output, blockers, schema gaps, or unfamiliar signals that should survive merge

Do not store:
- full source files
- long prose narratives
- raw scanner output
- unbounded call graphs

---

## Gate Lifecycle

Each deep semantic gate uses one of these statuses:
- `not_started`
- `in_progress`
- `partial`
- `blocked`
- `invalidated`
- `covered`

Rules:
- `covered` requires surface-specific gate requirements plus evidence refs and negative evidence.
- `partial`, `blocked`, `invalidated`, or missing gate output must become coverage debt when the surface remains security-relevant.
- `covered` is snapshot-scoped. It does not prove future or unchanged code safe.
- If a shared helper, dependency, config, parser, adapter, or trust boundary changes, invalidate dependent gates.
- A gate must be checkpointed after meaningful progress, especially before switching surfaces, delegating work, or final reporting.

---

## Required Gate Shape

Each entry in `deep_gate_ledger` should be compact and mergeable:

```json
{
  "id": "gate-authz-tenant-scope",
  "surface": "Authorization",
  "status": "partial",
  "owner": "supervisor",
  "scope": ["routes/api/v1/orders.py", "services/order_policy.py"],
  "trust_boundaries": [],
  "entry_points": [],
  "critical_dependencies": [],
  "design_claims": [],
  "implementation_evidence": [],
  "negative_evidence": [],
  "dependency_semantics_refs": [],
  "conflict_refs": [],
  "proof_obligation_refs": [],
  "evidence_observation_refs": [],
  "coverage_debt_refs": [],
  "last_checkpoint": "YYYY-MM-DD HH:MM:SS TZ"
}
```

Keep `implementation_evidence`, `negative_evidence`, and `evidence_observation_refs` as short references or one-sentence observations. Put detailed finding text in the report, not state.

---

## Surface-Specific Gate Contract

Every specialist module that defines a deep gate should answer:
- What exact sensitive details must be checked for this surface?
- Which implementation or dependency semantics commonly invalidate shallow conclusions?
- Which design claims or deployment assumptions must be verified?
- What negative evidence is required before calling the gate `covered`?
- What proof obligations remain if runtime evidence, environment, or cross-shard context is missing?

The specialist module owns the details. This core file owns persistence, state transitions, and mergeability.

---

## Design / Dependency / Implementation Conflicts

Treat conflicts as audit signals, not trivia.

Record a conflict when:
- documentation claims one trust boundary but code or config enforces another
- API specs, comments, or README examples imply a control that is absent in implementation
- a dependency's actual semantics differ from the code's assumptions
- production deployment exposure differs from the app's assumed exposure
- a mitigation exists on one route, helper, API version, or contract function but not a sibling path sharing the same invariant

Conflicts are not automatically confirmed vulnerabilities. Promote them only when current evidence shows a concrete unsafe path. Otherwise keep them as candidate signals, proof obligations, integration assumptions, or coverage debt.
If a conflict is high-signal but does not fit an existing vulnerability or gate shape, preserve it as an evidence observation with `schema_gap`, `unstructured_hypothesis`, or `custom:*` labels before deciding its report destination.

---

## Proof Obligations

Use `proof_obligations` for specific unanswered questions whose answer can change coverage, severity, or finding status.

Good proof obligations:
- "Confirm redirects are revalidated after the final resolved IP, not only before the first request."
- "Show every object mutation uses the same tenant-scoped canonical object selected by the policy check."
- "Verify Chainlink round completeness, answer bounds, and decimals normalization before collateral valuation."
- "Confirm uploaded SVG cannot become browser-executable through preview or CDN serving."

Bad proof obligations:
- "Review SSRF more."
- "Check auth."
- "Look at dependencies."

Each proof obligation should have an owner, related gate, next validation step, and status.

---

## Multi-Agent Rules

In beta `multi`:
- workers submit deep semantic deltas; they do not mark shared gates final
- the supervisor owns `deep_gate_ledger`, conflict normalization, final gate status, and coverage debt creation
- validators should receive precise proof obligations, not broad rescan prompts
- shared helpers, dependency semantics, deployment assumptions, and design conflicts should be represented once and referenced by gate IDs

If worker deltas disagree, code/config evidence beats summaries. Split the gate or keep it partial until the conflict is resolved.

---

## Recovery After Context Compression

After a context transition or long-running scan, reload audit state and reconstruct:
- active gates and statuses
- unresolved proof obligations
- design/dependency/implementation conflicts
- invalidated surfaces
- coverage debt candidates
- worker deltas awaiting supervisor merge

Do not rely on memory that a high-risk gate was "done" unless the persisted state has enough evidence refs to justify that status.
