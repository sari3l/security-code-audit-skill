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
- `coverage_delta`
  - counted review state for what was reviewed, partial, blocked, invalidated, time-boxed, or still pending inside the owned scope
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

### Handoff Request

```markdown
- **Type**: cross_shard_helper / followup_validation / ownership_conflict / compound_chain_review / severity_review
- **Reason**: [one sentence]
- **Related Surfaces**: [files, routes, helpers, services]
```
