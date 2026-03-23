# Swift Dependency Audit

## Detect

- `Package.swift`
- `Package.resolved`
- `Podfile.lock`
- `Cartfile.resolved`

## Audit Paths

Swift does not have one dominant universal native vulnerability audit command across all package managers. Prefer:
- the repo's existing SCA task if present
- `Package.resolved` or lock-file review
- external or generic SCA when available

Helpful supporting commands:

```bash
swift package show-dependencies
```

## What To Check

- package-manager drift between SwiftPM, CocoaPods, and Carthage
- server-side packages for Vapor and related HTTP/parsing stacks
- abandoned packages and stale pins
- vendored frameworks and binary targets

## Reporting Notes

- Be explicit when coverage relies on lock-file review or external SCA rather than native auditing.
- Treat binary targets and vendored frameworks as higher-risk because version visibility is weaker.
