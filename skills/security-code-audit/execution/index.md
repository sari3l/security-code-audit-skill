# Execution Mode Index

These files define execution topology. They are not part of `references/` because they control how the audit is executed, not what audit knowledge is loaded.

## Execution Modes

- `single`
  Default. One agent performs the full audit.

- `multi`
  Beta. Use multiple agents with a supervising agent coordinating the run.

If no execution parameter is provided, use `single`.

## Accepted Parameters

- positional: `single` or `multi`
- flag form: `--agents=single` or `--agents=multi`

Execution mode is a separate dimension from scan depth:
- depth: `quick` / `standard` / `deep`
- execution: `single` / `multi`

## Loading Guidance

1. Parse scan depth.
2. Parse execution mode.
3. Load this file.
4. Load exactly one execution file:
   - `execution/single-agent.md`
   - `execution/multi-agent.md`
5. If execution mode is `multi`, also load:
   - `execution/sharding.md`
   - `execution/merge.md`

## Design Intent

- `modes/`
  Controls scan depth.
- `execution/`
  Controls agent topology.
- `core/`
  Controls audit quality.
- `references/`
  Provides reusable audit knowledge.
