# Dependency Audit Index

This directory is separate from `references/application/vulnerabilities/` because C8 review is not only about weakness theory. It is also about package-manager behavior, lock-file semantics, transitive risk, vendored code, and future external SCA integration.

## When To Load

Load this directory whenever the repo contains any of:
- manifest files
- lock files
- vendored dependency trees
- container base images or package lists
- external SCA results

## Workflow

1. Detect every ecosystem present in the repo.
2. Load the matching ecosystem file(s) from this directory.
3. Before invoking native, external, or repo-configured audit tools, load `references/shared/tooling/command-resolution.md`, inspect safe repo scripts, probe the installed tool, and read current help so command names and flags come from the environment rather than memory.
4. Run the strongest native or repo-configured audit path that the ecosystem file recommends and command resolution confirms.
5. If results come from an external scanner, also load `references/shared/dependencies/sca-integration.md`.
6. Triage direct vs transitive, runtime vs dev-only, reachable vs unreachable, and base-image or vendored exposure.
7. Cross-reference dependency findings with code findings before final severity decisions.

## Ecosystem Modules

| Ecosystem | File | Typical Signals |
|-----------|------|-----------------|
| JavaScript / TypeScript | `references/shared/dependencies/javascript.md` | `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` |
| Python | `references/shared/dependencies/python.md` | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock` |
| Java | `references/shared/dependencies/java.md` | `pom.xml`, `build.gradle`, `gradle.lockfile` |
| Kotlin | `references/shared/dependencies/kotlin.md` | `build.gradle.kts`, version catalogs, Spring/Ktor Gradle builds |
| Go | `references/shared/dependencies/go.md` | `go.mod`, `go.sum`, `vendor/` |
| PHP | `references/shared/dependencies/php.md` | `composer.json`, `composer.lock` |
| Ruby | `references/shared/dependencies/ruby.md` | `Gemfile`, `Gemfile.lock` |
| Rust | `references/shared/dependencies/rust.md` | `Cargo.toml`, `Cargo.lock` |
| .NET / C# | `references/shared/dependencies/dotnet.md` | `*.csproj`, `Directory.Packages.props`, `packages.lock.json` |
| Swift | `references/shared/dependencies/swift.md` | `Package.swift`, `Package.resolved`, `Podfile.lock` |
| C / C++ | `references/shared/dependencies/c-cpp.md` | `conanfile*`, `vcpkg.json`, vendored `third_party/` trees |

## Cross-Cutting Checks

- runtime and framework EOL
- dev tooling accidentally deployed or exposed
- monorepo lock-file drift
- vendored or copied libraries outside the package manager
- container base-image and OS package exposure when app dependencies are clean
- private registries, feed trust, and package source pinning

## Deep Semantic Gate

In `deep` mode, create a `dependency_semantics` gate for each dependency or ecosystem whose behavior materially affects exploitability, remediation, parsing, trust, authorization, serialization, rendering, networking, storage, cryptography, or smart-contract semantics.

The gate is not `covered` until the audit records:
- actual dependency source of truth: manifest, lock file, vendored code, generated package graph, base image, deployment image, or runtime package list
- direct vs transitive and runtime vs dev/build-only exposure
- relevant dependency behavior, not only version: parser rules, escaping defaults, redirect handling, serializer typing, auth middleware order, ORM raw APIs, storage ACL/presign semantics, crypto defaults, or contract library behavior
- command-resolution evidence for native or repo-configured audit tooling, or a blocker/manual fallback
- negative evidence that a vulnerable or assumption-sensitive dependency is unreachable, dev-only, not shipped, or otherwise not part of the reviewed runtime
- proof obligations for runtime images, private registries, generated locks, base-image packages, or external SCA claims that cannot be verified locally

Record design/implementation conflicts when:
- docs or code assume one dependency behavior but the actual version, configuration, or transitive implementation behaves differently
- build and runtime install from different manifests or registries
- external SCA, native tooling, and lock-file inspection disagree and the difference affects risk

If dependency behavior materially affects a high-risk surface but cannot be verified, keep the gate `partial` or `blocked` and create coverage debt.

## External SCA

If the repo already has SCA output, or future automation fetches it from an external system, load:

- `references/shared/dependencies/sca-integration.md`

That file defines how to normalize remote results so they can be combined with native audit output without double counting.

## Related References

- `references/application/vulnerabilities/security-misconfiguration.md`
- `references/shared/reporting/coverage-matrix.md`
- `references/shared/reporting/finding-detail-standard.md`
