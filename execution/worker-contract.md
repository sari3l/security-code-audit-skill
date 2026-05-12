# Multi-Agent Worker Contract

Use this file only in beta `multi` execution.

## Goal

Make worker-to-supervisor communication structured, reviewable, and safe against both under-reporting and noisy over-reporting.

Workers do not communicate by improvising prose summaries alone.
They hand off normalized deltas that the `supervisor` can merge, reject, or route for follow-up.

---

## Core Rule

Only the `supervisor` may:
- update shared audit state
- merge worker output into final findings
- assign final severity, history status, and report wording

Workers may only submit structured handoffs.

---

## Required Handoff Fields

Every worker handoff should include:
- `meta`
  - `worker_role`
  - `owned_scope`
  - `loaded_modules`
- `project_context_delta`
  - verified claims, rejected claims, relevant invariants, git-change themes, and context conflicts discovered inside the owned scope
- `code_fact_delta`
  - newly observed entrypoints, routes, candidate sources, candidate sinks, state transitions, artifact surfaces, parser notes, and limitations inside the owned scope
- `evidence_observation_delta`
  - raw observations, tool-output summaries, blockers, negative evidence, schema gaps, and unknown-shaped signals that need supervisor routing
- `tool_invocation_delta`
  - command-resolution probes, executed scanner commands, skipped unsafe scripts, blockers, and manual fallbacks inside the owned scope
- `coverage_delta`
  - counted review state for what was reviewed, partial, blocked, invalidated, time-boxed, or still pending inside the owned scope
- `deep_gate_delta`
  - semantic gate status, evidence refs, negative evidence, dependency semantics, design/implementation conflicts, proof obligations, semantic assumptions, and coverage debt refs inside the owned scope
- `candidate_signals`
  - localized suspicious cases with concrete evidence and negative evidence
- `trace_delta`
  - new trace checkpoints, bounded paths, invalidations, and localized hypotheses
- `function_chain_delta`
  - bounded function-chain entries created or updated inside the owned scope
- `chain_candidates`
  - ways this worker's local issue may combine with another weakness, shared helper, or trust-boundary gap
- `agent_log_delta`
  - key worker decisions, blockers, and evidence checkpoints for shared audit state
- `handoff_requests`
  - explicit requests for supervisor routing or follow-up validation
- `blockers`
  - environment, ownership, or proof blockers that prevented stronger confirmation

Do not bury any of these inside a free-form narrative.

Workers must preserve unfamiliar but high-signal evidence as `evidence_observation_delta` with open labels such as `custom:*`; they should not discard it because the current handoff vocabulary is too narrow.

---

## Handoff Request Types

Use one or more of:
- `cross_shard_helper`
  A shared helper, parser, wrapper, or boundary appears outside the worker's owned scope.
- `followup_validation`
  A `validator` should attempt proof or bypass confirmation.
- `ownership_conflict`
  Current shard boundaries prevent confident attribution of scope or fix ownership.
- `compound_chain_review`
  Multiple small or moderate weaknesses may combine into materially higher impact.
- `severity_review`
  Local severity may change depending on another shard's evidence.

---

## False-Positive / False-Negative Guardrails

- Do not promote a chain just because it is imaginable.
- Do not suppress a low- or medium-severity bridge issue just because it is unimpressive in isolation.
- If a control looks partial, version-specific, or assumption-heavy, record the uncertainty instead of declaring the path safe.
- If a worker can prove only one step of a larger chain, keep the step plus the chain candidate.

The handoff contract exists to preserve signal, not to force premature certainty.

---

## Compound-Chain Rules

Workers must surface chain candidates when:
- a local finding unlocks a more dangerous sink, role, or trust boundary elsewhere
- a local weakness weakens the assumptions behind another worker's mitigation
- two medium or low issues together could produce materially higher exploitability or blast radius

Workers must not:
- assign final compound severity themselves
- merge multiple shard-local issues into one final finding on their own

That decision belongs to the `supervisor` after merge.

---

## Minimal Shapes

### Candidate Signal

```markdown
- **Title**: [short label]
- **Evidence**: [file / route / behavior]
- **Negative Evidence**: [what weakens confidence]
- **Why It Matters**: [local impact]
- **Needs**: [proof / cross-shard check / validator follow-up]
```

### Chain Candidate

```markdown
- **Local Step**: [what this worker found]
- **Combines With**: [shared helper / other shard / trust boundary]
- **Potential Impact**: [what changes if both are true]
- **Missing Proof**: [what still needs validation]
- **Requested Action**: [followup_validation / compound_chain_review]
```

### Function Chain Delta

```markdown
- **Function**: [module::function]
- **Why In Scope**: [sink / state transition / shared helper]
- **Entry Paths**: [routes, jobs, parent functions]
- **Join Checkpoints**: [helpers, parsers, guards]
- **Sink / Transition**: [dangerous sink or mutation]
- **Status**: bounded / open / blocked / invalidated
- **Truncation Or Blocker**: [one sentence]
```

### Agent Log Delta

```markdown
- **Stage**: [recon / scan / validation / report]
- **Summary**: [key decision or blocker]
- **Evidence Refs**: [files, routes, findings, or chain ids]
```

### Project Context Delta

```markdown
- **Claim**: [repo-authored or inferred claim]
- **Source**: [README, config, code, git metadata, API spec]
- **Expected Control**: [auth middleware, ingress, role guard, invariant check]
- **Verification Result**: unverified / validated / contradicted / partial / stale / not_applicable
- **Security Relevance**: [surface or invariant]
```

### Tool Invocation Delta

```markdown
- **Candidate**: [tool or repo script]
- **Resolution Source**: repo-configured / ecosystem-default / manual
- **Probe**: [command -v, --help, -h, version]
- **Executed Command**: [exact command or none]
- **Status**: executed / unavailable / unsupported / blocked / skipped_unsafe / manual_fallback
- **Limitation**: [one sentence if any]
```

### Deep Gate Delta

```markdown
- **Gate ID**: [stable local gate id]
- **Surface**: [Authorization / SSRF / Oracle / File Lifecycle / etc.]
- **Status**: not_started / in_progress / partial / blocked / invalidated / covered
- **Scope**: [owned files, routes, contracts, helpers, or dependency]
- **Evidence Refs**: [file:line, function, command result, dependency version]
- **Negative Evidence**: [what was checked that weakens the issue]
- **Dependency Semantics**: [library/framework behavior that matters, or none]
- **Design / Implementation Conflicts**: [claim vs code/config mismatch, or none]
- **Proof Obligations**: [specific remaining proof steps]
- **Coverage Debt Needed**: yes / no, with reason
```

### Handoff Request

```markdown
- **Type**: cross_shard_helper / followup_validation / ownership_conflict / compound_chain_review / severity_review
- **Reason**: [one sentence]
- **Related Surfaces**: [files, routes, helpers, services]
```
