# Bidirectional Tracing

Use this file when an audit decision depends on whether attacker-influenced input, repo-authored instructions, or other trust-boundary crossings can reach a security-sensitive sink or state-changing transition.

This is a quality-control module, not a domain-knowledge file. It defines how tracing works. Source families, sink families, and concrete grep starters still live in the active domain references.

---

## Purpose

Use bidirectional tracing to:
- avoid traditional one-way graph flooding from every apparent source
- converge on real attack paths by searching from both source and sink sides
- preserve compact trace checkpoints in audit state without turning `searched` into `safe`
- emit bounded per-function chain records that later attack-chain review can reuse
- stop expanding when the current path is bounded, not merely unexplored
- reason from parser, normalization, canonicalization, and trust-boundary behavior instead of memorizing payload lists

Do not use bidirectional tracing to:
- prove unchanged code is safe because a similar path was searched before
- expand every high-fanout helper or shared adapter by default
- replace concrete sink enumeration or profile-driven recon

---

## Core Model

Model the path as:

`source -> transformations / boundaries -> sink or state transition`

But do not search it as a one-way flood.

Instead:
1. enumerate high-signal candidate sources
2. enumerate high-signal candidate sinks or sensitive state transitions
3. create a bounded hypothesis linking the two sides
4. expand only along edges that make the hypothesis more or less credible

Prefer meet-in-the-middle reasoning over exhaustive graph expansion.

---

## Semantic Tracing Over Payload Catalogs

Treat proof strings and public POCs as examples, not as the vulnerability definition.

For any hypothesis, ask what each layer does to the attacker-shaped input:
- decode, split, trim, normalize, canonicalize, or re-encode it
- reinterpret it under a different grammar, type system, or path model
- drop one delimiter while preserving another
- restore attacker control after an earlier check appeared to constrain it

Look especially for parser or normalization differentials between:
- reverse proxy, web server, router, framework, and application helpers
- serializer, deserializer, object mapper, validator, and downstream sink
- filesystem path APIs, object-key builders, archive extractors, and OS-specific path rules

Examples such as encoded separators, semicolon-delimited path parameters, mixed slash handling, duplicate keys, content-type confusion, null-byte truncation, or type metadata are only surface forms.
The real question is whether the same attacker influence is interpreted differently across boundaries in a way that changes structure, authority, location, or execution.

Apply this lens across categories, not only injection:
- path traversal through path parsing and canonicalization drift
- deserialization through schema reduction failure or type re-materialization
- authn/authz through inconsistent subject, tenant, or route interpretation
- business logic through state transitions that look harmless locally but change downstream authority or money movement

---

## Candidate Selection

### Candidate Sources

Typical source families:
- request parameters, bodies, headers, cookies, path params, uploaded content
- repo-authored prompts, `SKILL.md`, `AGENTS.md`, templates, markdown, notebook outputs
- deserialized messages, queue payloads, webhook bodies, job inputs
- external contract calls, callback parameters, signatures, oracle values

### Candidate Sinks Or State Transitions

Typical sink families:
- raw SQL, shell/process execution, template evaluation, deserialization, prompt/tool invocation
- DOM or server-side rendering sinks
- privileged mutations, settlement/accounting transitions, upgrade/authz actions
- SSRF-capable fetches, file/path writes, archive extraction, signed URL issuance

Start from whichever side has the stronger signal first. If both sides are easy to enumerate, seed both.

---

## Convergence Rules

For each hypothesis:
- expand from the source side only if the next step narrows which sink family is reachable
- expand from the sink side only if the next step narrows which source family can influence it
- when both sides touch the same helper, wrapper, parser, sanitizer, policy gate, adapter, or boundary, treat that point as the join candidate
- prefer checking shared chokepoints before exploring many sibling leaf paths

Good reasons to continue:
- the next node is a shared helper used by the current hypothesis
- the next node crosses a trust boundary
- the next node decides structure, authority, or execution mode
- the next node can remove, preserve, or reintroduce attacker control

Bad reasons to continue:
- the node is merely adjacent in the call graph
- the node has high fan-out but no evidence it serves the current hypothesis
- the path only adds generic plumbing with no effect on attacker control

---

## Stop Conditions

Mark the current path as bounded or deprioritized when:
- a trusted invariant cuts the chain and no contradictory evidence appears
- an allowlist or fixed mapping removes attacker control over structure or authority
- the remaining expansion would only enumerate low-value fan-out with no stronger hypothesis
- a different sink family or source family has become the higher-signal route

Do not keep expanding only because the path is incomplete.
Do not bound a path prematurely when it is the only bridge into another open hypothesis or compound chain candidate.

---

## Shared-Node Rules

Treat these as checkpoints, not automatic full expansions:
- shared auth / authz middleware
- query builders and raw-query helper wrappers
- template wrappers, markdown renderers, prompt builders
- deserializers, parsers, object mappers, archive helpers
- routers, decoders, canonicalizers, path normalizers, and proxy adapters
- storage key/path builders, presign helpers, download gates
- proxy, upgrade, callback, registry, signer, and oracle adapters

For each checkpoint, answer:
- does this node participate in the active hypothesis?
- does it preserve attacker control, constrain it, or reintroduce it?
- if it changes later, which hypotheses and reviewed surfaces become invalid?

---

## State Semantics

When audit state is active, record compact trace checkpoints and hypotheses.

Hard rules:
- `searched` means "reviewed in the context of this hypothesis and snapshot"
- `searched` does not mean "safe"
- `bounded` means "current evidence says more expansion is low value unless assumptions change"
- `invalidated` means an upstream assumption, helper, parser, policy, or shared boundary changed enough that the old checkpoint can no longer be trusted
- partial or version-specific mitigations should narrow confidence, not erase the checkpoint

State should speed up re-orientation, not suppress fresh review.

---

## Function-Chain Outputs

For every security-relevant function or state-changing transition in scope, emit a bounded function-chain record into audit state.

Hard rules:
- record the chain at function granularity, not only at category granularity
- prefer entry path -> join checkpoints -> sink or state transition
- do not dump an unbounded recursive call graph just because more adjacent nodes exist
- if expansion stops early, record why it was bounded, blocked, or invalidated
- if the function is still in scope but no bounded chain can be written, create coverage debt instead of pretending it was covered

Each function-chain record should stay compact:
- `function`
- `why_in_scope`
- `entry_paths`
- `join_checkpoints`
- `sink_or_transition`
- `status`
- `truncation_or_blocker`
- `owner`

In beta `multi`, workers emit local chain deltas and the `supervisor` merges them into shared state.

---

## Relationship To Other Modules

- `core/bidirectional-tracing.md`
  Owns the tracing method, convergence rules, and state semantics.
- `references/application/*` and `references/smart-contract/*`
  Own source families, sink families, exploit patterns, and domain-specific review prompts.
- `references/shared/state-standard.md`
  Owns storage shape, invalidation fields, and run-context persistence for trace checkpoints and hypotheses.
