# security-code-audit

Code security audit skill for web/API, backend, full-stack, and smart-contract repositories.

`security-code-audit` is designed for code security review, SAST-style analysis, OWASP-style checks, dependency auditing, smart-contract review, and remediation retest. It focuses on real code, exploitability, and high-signal reporting instead of shallow pattern matching.

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
- audit mode: `quick` | `standard` | `deep` | `regression`
- execution mode: `single` | `multi`
- report style / output strategy: `governance` | `exploit-first` | `both`
- `governance` keeps the report root-cause-first and is the preferred internal reference for remediation governance, history, and regression.
- `exploit-first` makes attacker capability and blast radius more visible for external or non-specialist readers.
- `both` runs one audit and emits both concrete report styles; each saved report records `governance` or `exploit-first` in its filename and report metadata.
- audit mode, execution mode, and report style are independent axes
- `multi` is beta and falls back to `single` if the host cannot delegate

Examples:
- `/security-code-audit quick --report-style=exploit-first`
- `/security-code-audit deep --report-style=governance`
- `/security-code-audit regression --report-style=both`
- `/security-code-audit deep multi`
- `/security-code-audit deep --agents=multi --report-style=both`

What changed:
- report style is now a separate output axis from audit mode and execution mode
- when `both` is selected, the skill emits two independently labeled reports instead of one blended report
- report filenames use `.security-code-audit-reports/{YYYY-MM-DD-HHMMSS}-{mode}-{report-style}-{short-hash}.md`

Style examples:
- [Governance sample](docs/examples/report-styles/governance-sample.md)
- [Exploit-first sample](docs/examples/report-styles/exploit-first-sample.md)

## 2. Features

- Domain-aware auditing
  Recon selects the right knowledge domain so web/API and smart-contract audits do not get flattened into the same checklist.
- Real-code focus
  Findings are expected to be tied to actual file locations, exploit paths, and concrete minimal fixes.
- Repeated-pattern enumeration
  The skill is built to find all materially affected locations, not just the first hit.
- Evidence-gated findings
  Main findings stay limited to confirmed issues, while unresolved high-signal cases remain visible as candidate signals instead of being silently dropped.
- Dependency and artifact coverage
  Application code, dependencies, markdown/prompt artifacts, API specs, notebooks, and config surfaces all fit into the same audit flow.
- History and regression support
  Findings are compared against `.security-code-audit-reports/`, and `regression` mode can retest the latest report directly.
- Large-repo precision
  `.security-code-audit-state/` stores compact run context and re-audit hints so long scans keep their bearings.
- Honest coverage reporting
  Partial, blocked, or invalidated review areas are carried forward as coverage debt instead of being reported as fully covered.
- Deep/multi hypothesis tracking
  Deep mode and beta `multi` can carry forward material unresolved attack-chain or trust-boundary hypotheses in a dedicated appendix instead of losing them in scan notes.
- Optional multi-agent execution
  `multi` can widen coverage for large repos while keeping a single reporting path.

## 3. Architecture

Runtime architecture: staged scanning with profile routing, on-demand loading, and persistent state.

```mermaid
flowchart TD
    A["User command<br/>/security-code-audit [mode] [execution] [--report-style=...]"]
    B["SKILL.md<br/>entry router + shared workflow"]

    C["Bootstrap control plane<br/>parse mode + execution<br/>carry report-style request<br/>load core controls and mode rules"]
    D["Recon phase<br/>map repo surface, stack, artifacts, and risk areas"]
    E["Profile selection<br/>application | smart-contract | artifact-centric"]

    F["core/loading.md<br/>lazy loading + on-demand routing"]
    G["Primary knowledge domain<br/>references/application or references/smart-contract"]
    H["Shared modules<br/>artifacts, dependencies, reporting, and state standards"]

    I["Targeted audit pass<br/>follow selected references for the active surface"]
    J["Evidence and consolidation<br/>validate findings, dedupe repeats, track coverage debt"]
    K["Reporting and regression<br/>write one or two style-specific reports<br/>compare history, retest fixes"]

    S[".security-code-audit-state/<br/>run context, loading decisions, hypotheses, invalidations"]
    R[".security-code-audit-reports/<br/>human-readable findings and history"]

    A --> B
    B --> C
    C --> D
    D --> E
    E --> F

    F --> G
    F --> H

    G --> I
    H --> I
    I --> J
    J --> K
    K --> R

    D -. initialize scan state .-> S
    F -. persist selected modules .-> S
    I -. update findings and coverage .-> S
    J -. carry forward hypotheses and invalidations .-> S
    S -. support long scans, regression, and multi-agent continuity .-> I
    R -. latest report reused by regression mode .-> K
```

The skill is intentionally split into layers:

- `SKILL.md`
  Router and shared workflow.
- `core/`
  Anti-hallucination, coverage, findings, severity, and lazy-loading controls.
- `profiles/`
  Target semantics after recon: application, smart-contract, or artifact-centric.
- `references/application/`
  Primary methodology for web/API/backend audits.
- `references/smart-contract/`
  Primary methodology for Solidity and on-chain audits.
- `references/shared/`
  Artifacts, dependencies, reporting, and audit-state standards shared across domains.
- `modes/`
  `quick`, `standard`, `deep`, and `regression`.

Output layers:
- `.security-code-audit-reports/`
  Human-readable findings and history.
- `.security-code-audit-state/`
  Machine-readable run context for large, long-running, or high-complexity scans.
