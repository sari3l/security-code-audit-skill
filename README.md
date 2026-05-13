# security-code-audit

Current release: `v1.0.9`

Code security audit skill for web/API, backend, full-stack, smart-contract, and artifact-centric repositories.

`security-code-audit` is designed for code security review, SAST-style analysis, OWASP-style checks, dependency auditing, smart-contract review, artifact and prompt-surface review, and remediation retest. It focuses on real code, exploitability, bounded tracing, persistent audit state, and high-signal reporting instead of shallow pattern matching.

Chinese documentation: [README-CN.md](README-CN.md)

## 1. Usage

- `/security-code-audit`
  Default full audit. Equivalent to `standard single`.
- `/security-code-audit quick`
  Fast high-risk triage.
- `/security-code-audit deep`
  Exhaustive review with stronger verification and attack-chain depth.
- `/security-code-audit regression`
  Retest the latest report and verify whether fixes actually hold.
- `/security-code-audit help`
  Show parameters, modes, execution options, and examples.

Parameters:
- depth: `quick` | `standard` | `deep` | `regression`
- execution: `single` | `multi`
- `multi` is beta and falls back to `single` if the host cannot delegate

Examples:
- `/security-code-audit deep multi`
- `/security-code-audit regression`
- `/security-code-audit deep --agents=multi`

## 2. Core Capabilities

- Target-aware routing
  Recon selects a target profile first, then routes into the right knowledge domain and shared modules for the observed surface.
- Real-code focus
  Findings are expected to be tied to actual file locations, exploit paths, and concrete minimal fixes.
- Bounded tracing
  Bidirectional tracing keeps source-to-sink and state-transition analysis focused on real trust-boundary crossings instead of unbounded graph expansion.
- Repeated-pattern enumeration
  The skill is built to find all materially affected locations, not just the first hit.
- Audit-state continuity
  `.security-code-audit-state/` stores compact run context, code fact snapshots, evidence observations, loaded-module decisions, function-chain records, and invalidations so every run can re-orient cleanly.
- Dependency and artifact coverage
  Application code, dependencies, markdown and prompt artifacts, API specs, notebooks, config, and IaC surfaces all fit into the same audit flow.
- Honest coverage reporting
  Partial, blocked, or invalidated review areas are carried forward as coverage debt instead of being reported as fully covered.
- Evidence-gated findings
  Main findings stay limited to confirmed issues, while unresolved high-signal cases remain visible as candidate signals or working hypotheses instead of being silently dropped.
- History and regression support
  Findings are compared against `.security-code-audit-reports/`, and `regression` mode can retest the latest report directly after a fresh current-state pass or report-baseline selection.
- Optional multi-agent execution
  `multi` can widen coverage for large repos while keeping a single reporting path.

## 3. Architecture

Runtime architecture: staged scanning with mode policy, execution topology, state freshness checks, profile routing, advisory code facts, evidence observation routing, lazy loading, bounded tracing, and persistent state.

```mermaid
flowchart TD
    A["User command<br/>/security-code-audit [mode] [execution]"]
    B["SKILL.md<br/>entry router + shared workflow"]
    MP["Mode policy<br/>quick | standard | deep | regression<br/>scope, depth, stop conditions"]
    C["Bootstrap control plane<br/>parse mode and execution<br/>load core, execution, mode rules"]
    X["Execution topology<br/>single | multi<br/>ownership, sharding, worker contract, merge"]

    ST[".security-code-audit-state<br/>machine-readable continuity state"]
    SR["State reader<br/>freshness, invalidation,<br/>continuation, merge hints<br/>not safety proof"]

    D["Recon phase<br/>map repo surface, stack, artifacts,<br/>claims, risk areas, and state freshness"]
    RUI["core/untrusted-repo-input.md<br/>repo docs, comments, old reports,<br/>and claims are hints only"]
    PC["core/project-context.md<br/>verified claims, business invariants,<br/>trust-boundary assumptions,<br/>deployment assumptions, change themes"]
    CF["core/surface-profile.md<br/>surface profile + code_fact_snapshot<br/>entrypoints, routes, sinks,<br/>state transitions, artifacts, limitations"]
    CB["Audit context bundle<br/>observed surfaces, business assets,<br/>invariants, trust boundaries,<br/>code facts, limitations, invalidations"]

    E["Profile selection<br/>application | smart-contract | artifact-centric"]
    F["core/loading.md<br/>lazy loading + on-demand routing"]
    G["Primary knowledge domain<br/>application | smart-contract"]
    H["Shared modules<br/>artifacts, dependencies, tooling,<br/>reporting, and state standards"]
    T["Core quality controls<br/>integrity, coverage, findings,<br/>severity, fingerprints, tracing"]
    Q["core/deep-semantic-controls.md<br/>deep, multi, or complex high-risk surfaces"]
    U["Optional advisory tooling<br/>references/shared/tooling/command-resolution.md<br/>repo command resolution and scanner evidence,<br/>not the audit backbone"]

    I["Hypothesis-driven audit pass<br/>generate, validate, falsify, bound<br/>current-code discovery depth controlled by mode"]
    EO["Evidence observation envelope<br/>raw observations, tool output, blockers,<br/>negative evidence, schema gaps, custom signals"]
    J["Evidence and consolidation<br/>route observations, validate findings,<br/>dedupe repeats, reconcile gates, tools,<br/>and coverage debt"]
    HM["Historical miss gate<br/>reopen prior findings against current code<br/>before lifecycle labels"]
    K["Reporting and regression<br/>write findings, compare history, retest fixes"]

    R[".security-code-audit-reports/<br/>human-readable findings and history"]

    A --> B
    B --> MP
    B --> C
    C --> X
    ST -. read .-> SR
    SR -. freshness and invalidation .-> D
    SR -. continuation and open obligations .-> CB
    SR -. merge ledgers and coverage state .-> J
    MP --> D
    X --> D
    RUI --> D
    D --> PC
    D --> CF
    PC --> CB
    CF --> CB
    CB --> E
    E --> F
    F --> G
    F --> H
    F --> T
    F --> Q
    H --> U
    MP --> I
    X --> I
    G --> I
    H --> I
    T --> I
    Q -. conditional semantic controls .-> I
    U -. optional scanner evidence .-> I
    U -. tool-output observations<br/>and blockers .-> EO
    I --> EO
    EO --> J
    J --> HM
    HM --> K
    K --> R
    X -. persist topology and merge inputs .-> ST
    D -. persist run context .-> ST
    PC -. persist project context .-> ST
    CF -. persist code facts and limitations .-> ST
    F -. persist selected modules .-> ST
    U -. persist command probes and blockers .-> ST
    EO -. preserve observations before routing .-> ST
    I -. update traces, tools, gates, coverage .-> ST
    J -. persist hypotheses, obligations, invalidations .-> ST
    HM -. persist historical misses or lifecycle allowance .-> ST
    R -. regression input only .-> K
```

`State reader` is a conceptual operation, not a new runtime service or file. It reads prior state for freshness, invalidation, continuation, and merge hints, then treats those hints as orientation rather than safety proof.

The skill is intentionally split into layers:

| Path | Purpose |
| --- | --- |
| `SKILL.md` | Router, help path, shared workflow, and progress rules |
| `core/` | Integrity, coverage, findings, severity, project context, lazy loading, surface profiles, advisory code facts, bidirectional tracing, and deep semantic controls |
| `execution/` | Single-agent and beta multi-agent topology, worker contracts, sharding, and merge rules |
| `profiles/` | Post-recon target semantics: `application`, `smart-contract`, or `artifact-centric` |
| `references/application/` | Primary methodology for web/API/backend audits |
| `references/smart-contract/` | Primary methodology for Solidity and on-chain audits |
| `references/shared/` | Shared artifact, dependency, tooling, reporting, and audit-state standards |
| `modes/` | `quick`, `standard`, `deep`, and `regression` depth contracts |

Output layers:

| Path | Purpose |
| --- | --- |
| `.security-code-audit-reports/` | Human-readable findings, history, regression baselines, and action items |
| `.security-code-audit-state/` | Machine-readable run context, surface inventories, project context, code fact snapshots, evidence observations, tool invocation records, deep gate ledgers, function chains, hypotheses, and invalidations for every run |
