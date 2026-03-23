# Go Dependency Audit

## Detect

- `go.mod`
- `go.sum`
- `vendor/`
- `replace` directives

## Preferred Audit Paths

```bash
govulncheck ./...
go list -m all
go mod graph
```

## What To Check

- direct vs transitive vulnerable modules
- `replace` directives that pin forks or stale local paths
- vendored modules that diverge from `go.sum`
- reachable vulnerable symbols vs modules present but unused
- outdated Go runtime version
- parser, archive, auth, JWT, HTTP, template, and proxy libraries

## Common High-Risk Cases

- the module graph looks clean but `vendor/` contains stale code
- a vulnerable package is only pulled through tooling, but the tool is embedded in release or admin paths
- `govulncheck` flags symbol reachability that deserves higher confidence than lock-file-only matching

## Reporting Notes

- Record whether the vulnerable code path is symbol-reachable.
- Mention any mismatch between `go.mod`, `go.sum`, and vendored code.
