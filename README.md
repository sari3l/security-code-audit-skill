# Security Code Audit

Current release: `v4.1.0`

A code security audit skill for web/API, service, smart-contract, deployment, CI,
and instruction-bearing repositories. Chinese documentation: [README-CN.md](README-CN.md).

## Usage

- `/security-code-audit`: default `deep single` discovery
- `/security-code-audit quick`: incremental semantic review with a global dangerous-capability census
- `/security-code-audit standard`: full discovery with practical semantic depth
- `/security-code-audit deep`: stronger invariant, trust-boundary, and attack-chain closure
- `/security-code-audit regression`: retest the latest usable report
- `/security-code-audit help`: show options without starting an audit
- `/security-code-audit deep --auto-fix`: prepare isolated remediation after the audit;
  commit and merge still require separate acceptance of the reviewed changes

Optional `multi` execution requires explicit selection and host support.

## Capabilities

- Current-source discovery, bidirectional tracing, and repeated-pattern enumeration
- Immutable dangerous-capability seeds, source snapshot validation, and exact report references
- Open exploration with durable branch records and disconfirmation evidence
- Safe local execution boundaries, fresh verification, and stable coverage identity
- Application and contract authorization, state, integration, and settlement review
- Persistent audit state, report rendering, history comparison, and remediation worktrees
- Provider-independent requirement context after architecture/change reconnaissance

Reports and state live in the running directory's `output/` using the
`security-code-audit-` prefix. See [SKILL.md](SKILL.md) for the execution contract.

## Plugin distributions

The public distribution includes the generic [plugin framework](plugins/README.md),
schema, and metadata validator. Optional provider implementations may be bundled
in the internal distribution. An installation with no configured provider records
`not_configured` and continues the full audit.

Validate installed plugin metadata with `python3 tools/audit_plugin_check.py`.
Credentials belong in user environment/configuration, outside the repository.
