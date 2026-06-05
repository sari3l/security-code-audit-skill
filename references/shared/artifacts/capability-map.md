# Capability Map Review

Use this module for skill, agent, prompt, plugin, setup-flow, and instruction-bearing repositories when operator-directed behavior or tool authority is part of the security surface.

The capability map is an advisory representation, not a closed intermediate representation. It helps reviewers structure evidence, but it must not erase unfamiliar signals or prevent confirmed findings that satisfy the evidence standard.

---

## Purpose

Build a compact map of what the artifact can cause an operator, agent, tool, or runtime to do:
- actions and triggers
- gates and approval requirements
- local resources and secrets touched
- process, network, filesystem, environment, browser-profile, dependency, persistence, and agent-call effects
- source-to-sink paths and their current evidence status
- documented safety claims and contradictions with observed behavior

---

## Core Records

Preferred JSONL outputs when the optional Python assurance layer is used:
- `raw-observations.jsonl`
- `unmapped-signals.jsonl`
- `capabilities.jsonl`
- `capability-paths.jsonl`
- `capability-claims.jsonl`

Every decision-supporting record should include:
- `id`
- `scope`
- `freshness_status`
- `evidence_refs`

Capability records should include:
- `trigger`: `manual`, `external`, `llm`, `on_import`, `on_install`, `scheduled`, or `unknown`
- `gate_strength`: `strong`, `weak`, `none`, or `unknown`
- `effects`: open-world list with preferred labels such as `proc_exec`, `code_eval`, `fs_read`, `fs_write`, `env_read`, `env_write`, `net_read`, `net_write`, `agent_call`, `browser_profile_access`, `persistence`, and `dependency_mutation`
- `sources`: user, repo, remote, secret, sensitive-local, environment, browser-profile, or custom labels
- `sinks`: process, network, filesystem, environment, browser-profile, dependency environment, agent, host startup, or custom labels
- `resources`: concrete paths, URLs, environment variable names, commands, or redacted sensitive identifiers
- `path_status`: `confirmed`, `candidate`, `blocked`, `bounded`, `negative_evidence`, `coverage_debt`, or `unmapped_signal`

Unknown values are not discarded. Preserve them in `extensions`, `unmapped-signals.jsonl`, or `evidence-observations.jsonl` with `schema_gap` / `custom:*` labels.

---

## Gate Model

Strong gates:
- explicit human approval immediately before a dangerous action
- per-run confirmation that shows the relevant command, destination, file path, or secret use
- out-of-band authorization that the artifact cannot silently bypass

Weak gates:
- broad safety prose
- allowlists whose destination, payload, or runtime binding was not verified
- budget limits, credential scoping, or "read only" claims without enforcement evidence
- setup instructions that assume a trusted operator without showing what will run

No gate:
- automatic install/import/scheduled behavior
- hidden helper scripts or command wrappers
- remote bootstrap chains
- instructions that pass untrusted content to an agent or shell without review

Weak or absent gates do not automatically create confirmed findings, but they must affect path status, candidate notes, or coverage debt for dangerous capabilities.

---

## Claim Contradictions

Treat repo-authored safety language as a claim to verify:
- `read_only` conflicts with `fs_write`, `env_write`, `dependency_mutation`, `net_write`, `persistence`, or `proc_exec`
- `local_only` / `no_network` conflicts with `net_read`, `net_write`, or `agent_call`
- `no_fs_write` conflicts with `fs_write` or `persistence`
- `credential_bound` conflicts with secrets flowing into unrelated actions or egress paths

Contradictions are signals. Promote them only when current evidence shows a credible unsafe path; otherwise route them to candidates, hypotheses, negative evidence, or coverage debt.

---

## Required Review

For skill/agent/instruction-bearing repos:
1. Inventory instruction-bearing files, tool manifests, setup docs, wrappers, and hidden helpers.
2. Seed or manually record raw observations for high-risk instructions and resources.
3. Normalize what can be safely normalized into capabilities and paths.
4. Preserve unfamiliar or unmodeled signals as `schema_gap` / `unmapped_signal`.
5. Trace dangerous effects to sources, sinks, gates, and negative evidence.
6. Reconcile safety claims against observed effects.
7. Route every material raw observation to confirmed finding, candidate, negative evidence, coverage debt, working hypothesis, integration assumption, or Skill Optimization Suggestion.

Coverage is incomplete when material capability paths, raw observations, or unmapped signals remain unrouted.
