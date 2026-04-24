# Kotlin + Spring Security Reference

## Identification Features

```bash
grep -r "@SpringBootApplication\|@RestController\|@Configuration" --include="*.kt"
grep -r "spring-boot\|org.springframework" --include="*.kts" --include="*.gradle" --include="*.yml"
grep -r "data class .*Request\|@RequestBody" --include="*.kt"
```

Common file patterns: `Application.kt`, `controller/`, `service/`, `config/`, `application.yml`.

---

## High-Risk Framework Surfaces

### 1. Kotlin Data-Class Binding

- `data class` request DTOs exposing `role`, `tenantId`, `balance`, or workflow fields
- nullable fields hiding partial-update assumptions
- Jackson / Kotlin module defaults accepting broad input into privileged models

### 2. Spring Security Parity

- Java-config assumptions copied into Kotlin but missing route coverage
- `@PreAuthorize` absent on service methods because controller auth "looks enough"

### 3. Persistence Escape Hatches

- `JdbcTemplate`, `EntityManager`, native queries, MyBatis mappers inside Kotlin services
- dynamic sort or field names passed from controllers

---

## Detection Commands

```bash
grep -rn '@RequestBody|data class .*Request|data class .*Dto' --include="*.kt"
grep -rn '@PreAuthorize|SecurityFilterChain|authorizeHttpRequests' --include="*.kt"
grep -rn 'JdbcTemplate|createNativeQuery|createQuery\\(|FromSql|sort|order' --include="*.kt"
grep -rn 'role|tenantId|ownerId|balance|isAdmin|approved' --include="*.kt"
```

---

## Audit Questions

- Are Kotlin request DTOs narrow enough for create and patch flows?
- Is method-level auth used where controller-level auth is insufficient?
- Do nullability and default values accidentally widen accepted input?
- Are Kotlin services hiding raw SQL or authorization logic that controllers do not enforce?
