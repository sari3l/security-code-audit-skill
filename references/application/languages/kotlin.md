# Kotlin Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers Spring Boot, Ktor, Android, background workers, and Kotlin/JVM service patterns.

---

## Language-Specific Hotspots

- `JdbcTemplate`, `EntityManager`, `jOOQ`, and raw SQL interpolation
- Jackson / kotlinx serialization binding directly into entities or data classes with privileged fields
- Spring Security / Ktor auth gaps hidden by concise DSLs
- Android cleartext traffic, exported components, and token storage mistakes

---

## C1: Injection

### Key Questions
- Are SQL, shell, expression, or template strings built via interpolation?
- Can user input reach `ProcessBuilder`, `Runtime.exec`, `JdbcTemplate`, or `EntityManager.createQuery`?
- Are `Regex`, `Pattern`, or parser APIs attacker-controlled in high-cost contexts?
- Are YAML / XML / serialization features configured unsafely?

### Dangerous Patterns

```kotlin
val sql = "SELECT * FROM users WHERE email = '$email'"
jdbcTemplate.queryForList(sql)

Runtime.getRuntime().exec("tar -xf $archive")

val query = entityManager.createQuery("from User where name = '$name'")
```

### Detection

```bash
grep -rn 'JdbcTemplate|createNativeQuery|createQuery\\(|FromSql|sql\\s*=\\s*".*\\$' --include="*.kt" --include="*.kts"
grep -rn 'Runtime\\.getRuntime\\(\\)\\.exec|ProcessBuilder\\(' --include="*.kt"
grep -rn 'Regex\\(|Pattern\\.compile\\(|ObjectInputStream|Yaml|DocumentBuilderFactory' --include="*.kt"
```

---

## C2: Authentication

### Key Questions
- Is Spring Security or Ktor auth applied consistently across all routes?
- Are JWT validators checking issuer, audience, expiry, and algorithm explicitly?
- Are passwords hashed with bcrypt / argon2 and compared safely?
- Are Android tokens stored in EncryptedSharedPreferences / Keystore rather than plain preferences?

### Detection

```bash
grep -rn 'SecurityFilterChain|authorizeHttpRequests|install\\(Authentication\\)|jwt|JWT|NimbusJwtDecoder' --include="*.kt"
grep -rn 'BCrypt|Argon2|MessageDigest|SharedPreferences|EncryptedSharedPreferences|KeyStore' --include="*.kt"
grep -rn 'resetPassword|otp|magic|mfa|rememberMe' --include="*.kt"
```

---

## C3: Authorization

### Key Questions
- Are resource queries scoped by owner or tenant instead of plain IDs?
- Are role checks attached to handlers and services, not just controllers?
- Are admin endpoints, actuator routes, and internal APIs separated clearly?
- Are Android exported components guarded against unauthorized callers?

### Detection

```bash
grep -rn 'findById\\(|getReferenceById\\(|@PathVariable|call.parameters' --include="*.kt"
grep -rn '@PreAuthorize|hasRole|hasAuthority|authorize\\(|policy' --include="*.kt"
grep -rn 'android:exported|permission=' --include="AndroidManifest.xml"
```

---

## C4: Mass Assignment

### Key Questions
- Are `@RequestBody` or Ktor payloads decoded directly into entities with privileged fields?
- Do data classes include `role`, `isAdmin`, `tenantId`, `balance`, or approval flags?
- Are PATCH handlers copying arbitrary maps into models?
- Are Jackson polymorphic or reflection-based binders setting fields beyond intent?

### Dangerous Patterns

```kotlin
data class UserUpdate(
    val name: String?,
    val role: String?,
    val balance: Long?,
)

@PostMapping("/profile")
fun update(@RequestBody user: UserEntity) = repo.save(user)
```

### Detection

```bash
grep -rn '@RequestBody|receive<|call.receive<|ObjectMapper\\(' --include="*.kt"
grep -rn 'role|isAdmin|tenantId|ownerId|balance|creditLimit|approved' --include="*.kt"
grep -rn 'copy\\(|BeanUtils|ReflectionUtils|MutableMap<String, Any>' --include="*.kt"
```

---

## C5: Data Exposure

### Key Questions
- Do data classes, serializers, or `toString()` outputs leak secrets?
- Are debug logs, exception handlers, or actuator endpoints exposing internal data?
- Are Android backups, local databases, or exported files leaking tokens?
- Are stack traces or validation errors returned verbosely to clients?

### Detection

```bash
grep -rn 'data class .*token|password|secret|toString\\(|logger\\.|printStackTrace\\(' --include="*.kt"
grep -rn 'management\\.endpoints|show-details|include-stacktrace|server.error' --include="*.yml" --include="*.properties"
grep -rn 'allowBackup|fullBackupContent' --include="AndroidManifest.xml"
```

---

## C6: Security Misconfiguration

### Key Questions
- Are CORS, CSRF, cookies, and headers configured safely?
- Are Actuator, H2 console, GraphiQL, or debug tooling exposed?
- Is Android cleartext traffic or broad network security config enabled?
- Are dev profiles, sample creds, or test routes reachable in production?

### Detection

```bash
grep -rn 'cors|csrf|sameSite|secure|httpOnly|h2-console|actuator|graphiql' --include="*.kt" --include="*.yml" --include="*.properties"
grep -rn 'usesCleartextTraffic|networkSecurityConfig|android:debuggable' --include="AndroidManifest.xml" --include="*.xml"
```

---

## C7: XSS

### Key Questions
- Are Thymeleaf, Mustache, Freemarker, or kotlinx.html templates bypassing escaping?
- Is user-controlled HTML inserted into WebView or server-rendered pages?
- Are values embedded into inline JavaScript or attribute contexts unsafely?
- Are markdown and rich-text flows sanitized before rendering?

### Detection

```bash
grep -rn 'th:utext|\\?no_esc|unsafe\\s*\\{|WebView|loadDataWithBaseURL|evaluateJavascript' --include="*.html" --include="*.ftl" --include="*.kt"
grep -rn 'markdown|sanitize|Jsoup.clean' --include="*.kt"
```

---

## C8: Dependencies

### Review Checklist
- Review Gradle dependencies, BOMs, plugin versions, and transitive serializers.
- Run `gradle dependencyCheckAnalyze` or equivalent SCA tooling.
- Check Spring Boot, Ktor, Jackson, Netty, OkHttp, and AndroidX security posture.
- Flag EOL JDK, Kotlin, AGP, and framework versions.

### Detection

```bash
find . -name "build.gradle" -o -name "build.gradle.kts" -o -name "gradle.properties"
grep -rn 'implementation\\(|api\\(|classpath\\(|id\\(' build.gradle build.gradle.kts
```

---

## C9: Cryptography

### Key Questions
- Are secrets generated with `SecureRandom`, not `Random()`?
- Are passwords hashed with modern libraries, not `MessageDigest` directly?
- Are Android keys stored in Keystore and server keys outside code?
- Are HMAC or signature checks constant-time?

### Detection

```bash
grep -rn 'SecureRandom|Random\\(|MessageDigest|Mac\\(|Cipher\\(' --include="*.kt"
grep -rn 'AndroidKeyStore|KeyGenParameterSpec|PBKDF2|bcrypt|argon2' --include="*.kt"
grep -rn 'AES/ECB|DES|RC4|MD5|SHA-1' --include="*.kt"
```

---

## C10: SSRF

### Key Questions
- Can user URLs reach `RestTemplate`, `WebClient`, `OkHttp`, or download/import features?
- Are redirects, localhost, metadata IPs, alternate encodings, and DNS rebinding blocked?
- Are webhook or callback URLs revalidated on every request?
- Are proxy settings or service discovery shortcuts weakening egress controls?

### Detection

```bash
grep -rn 'RestTemplate|WebClient|OkHttpClient|URL\\(|URI\\(' --include="*.kt"
grep -rn 'followRedirects|proxy|169\\.254\\.169\\.254|127\\.0\\.0\\.1|localhost|::1' --include="*.kt"
```

---

## C11: Logging & Monitoring

### Key Questions
- Are tokens, auth headers, or request bodies logged?
- Can user input forge log entries or high-cardinality labels?
- Are permission denials and auth failures audited?
- Are Sentry / Crashlytics / APM integrations capturing sensitive payloads?

### Detection

```bash
grep -rn 'logger\\.|KotlinLogging|Timber|Crashlytics|Sentry' --include="*.kt"
grep -rn 'Authorization|password|token|secret|cookie|body' --include="*.kt"
```

---

## C12: Infrastructure & Platform

### Key Questions
- Are containers and JVM processes running with least privilege?
- Are CI secrets, signing keys, and release credentials stored safely?
- Are Android manifests, backup settings, and file providers scoped correctly?
- Are server configs, pods, or systemd units exposing broad filesystem or network access?

### Detection

```bash
find . -name "Dockerfile" -o -name "docker-compose.yml" -o -name ".github" -o -name "*.service"
grep -rn 'USER root|JAVA_TOOL_OPTIONS|SPRING_PROFILES_ACTIVE=dev|android:exported|grantUriPermissions' --include="Dockerfile" --include="*.yml" --include="*.service" --include="AndroidManifest.xml"
```
