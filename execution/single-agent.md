# Single-Agent Execution

Default execution mode.

## Use When

- no execution parameter is provided
- the repo is small or medium
- low coordination overhead matters more than parallel breadth
- the host does not support sub-agents

## Rules

- one agent owns the full audit lifecycle
- still use `core/` controls for integrity, coverage, findings, and severity
- do not simulate fake sub-agents in prose

## Strengths

- lowest coordination overhead
- simplest severity and finding consistency
- best default for quick mode and most standard audits
