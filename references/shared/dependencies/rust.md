# Rust Dependency Audit

## Detect

- `Cargo.toml`
- `Cargo.lock`
- workspace manifests

## Preferred Audit Paths

```bash
cargo audit
cargo tree -i <crate>
```

If the repo already uses `cargo deny`, include that result too.

## What To Check

- vulnerable direct and transitive crates
- workspace version drift
- yanked or unmaintained crates
- feature flags that pull in risky parsers or crypto implementations
- unsafe wrapper crates around archive, parser, serialization, and network code

## Common High-Risk Cases

- one workspace member updates while another still pins the old crate through lock-file churn
- patched forks hide the actual advisory path
- a vulnerable crate only appears behind a feature flag that is enabled in production

## Reporting Notes

- Record the crate path from `cargo tree` when available.
- Note whether the issue depends on a production-enabled feature set.
