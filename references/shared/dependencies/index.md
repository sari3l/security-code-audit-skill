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
3. Run the strongest native or repo-configured audit path that the ecosystem file recommends.
4. If results come from an external scanner, also load `references/shared/dependencies/sca-integration.md`.
5. Triage direct vs transitive, runtime vs dev-only, reachable vs unreachable, and base-image or vendored exposure.
6. Cross-reference dependency findings with code findings before final severity decisions.

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

## External SCA

If the repo already has SCA output, or future automation fetches it from an external system, load:

- `references/shared/dependencies/sca-integration.md`

That file defines how to normalize remote results so they can be combined with native audit output without double counting.

## Related References

- `references/application/vulnerabilities/security-misconfiguration.md`
- `references/shared/reporting/coverage-matrix.md`
- `references/shared/reporting/finding-detail-standard.md`
