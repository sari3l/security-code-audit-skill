# Java Dependency Audit

## Detect

- `pom.xml`
- `build.gradle`
- `build.gradle.kts`
- `gradle.lockfile`
- version catalogs and multi-module build roots

## Audit Paths

Java has no single universal built-in audit command. Prefer the repo's existing SCA task if one is already configured.

Supporting commands:

```bash
./mvnw dependency:tree
mvn dependency:tree
./gradlew dependencies
gradle dependencies
```

If the repo already defines an SCA plugin task such as OWASP Dependency-Check or a corporate scanner, run that existing task instead of inventing a new path.

## What To Check

- vulnerable direct and transitive packages in dependency trees
- shaded, fat, or uber JARs that hide old libraries
- framework and runtime EOL
- stale Spring, Jackson, SnakeYAML, Log4j, Commons FileUpload, and similar high-risk libraries
- per-module version drift in monorepos
- packages pulled from private repositories without pinning or review

## Common High-Risk Cases

- one microservice upgraded while another still uses the old shared starter
- dependency management in parent POM or version catalog masks the real child version
- scanner only checks Maven while the repo actually builds with Gradle
- container image includes old Java runtime or OS packages not visible in the build graph

## Reporting Notes

- Record whether the result came from a repo-configured SCA task, dependency tree review, or external SCA.
- For transitive issues, include the dependency chain when available.
