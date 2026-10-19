# security-code-audit

Current release: `v4.0.0`

High-recall code security audit skill for web/API, backend, full-stack, smart-contract, deployment, CI, and instruction-bearing repositories.

The runtime supports quick, standard, deep, and regression modes; dangerous-capability census, bounded tracing, persistent audit state, requirements-context integration, isolated remediation worktrees, and evidence-gated reporting.

This distribution includes the optional Onyx requirements-context plugin under [`plugins/onyx`](plugins/onyx/README.md). It ships with disabled placeholder configuration; credentials and real endpoints stay in user environment/configuration.

Chinese documentation: [README-CN.md](README-CN.md)

Usage:

- `/security-code-audit` — deep current-code discovery
- `/security-code-audit quick` — incremental high-risk review
- `/security-code-audit standard` — full practical review
- `/security-code-audit regression` — retest the latest usable report
- `/security-code-audit help` — show command options
