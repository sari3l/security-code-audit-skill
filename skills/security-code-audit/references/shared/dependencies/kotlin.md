# Kotlin Dependency Audit

## Detect

- `build.gradle.kts`
- `settings.gradle.kts`
- Gradle version catalogs
- Spring or Ktor multi-module builds

## Audit Paths

Kotlin server projects usually share the Java dependency ecosystem. Start with:

```bash
./gradlew dependencies
gradle dependencies
```

If the repo already defines a security scan task, use that configured Gradle path. Otherwise treat Kotlin dependency review as Gradle/Maven graph analysis plus external or generic SCA where available.

## What To Check

- Spring or Ktor transitive dependency chains
- version catalog drift across modules
- plugin and buildscript dependencies that may affect CI or artifact production
- runtime/framework EOL
- serializer, template, HTTP client, archive, and auth libraries

## Reporting Notes

- If the repo is really a JVM multi-module build, cross-load `references/shared/dependencies/java.md`.
- Only treat Android-specific guidance as in-scope if the repo clearly targets mobile.
