# Spring Boot/Java Framework - Security Vulnerability Reference

## Identification Features

```bash
# Detect Spring Boot usage
grep -r "spring-boot\|springframework" --include="*.xml" --include="*.gradle" --include="*.kts"
grep -r "@SpringBootApplication\|@RestController\|@Controller" --include="*.java" --include="*.kt"
grep -r "spring.datasource\|spring.jpa\|server.port" --include="*.properties" --include="*.yml" --include="*.yaml"
find . -name "pom.xml" -exec grep -l "spring-boot" {} \;
find . -name "build.gradle" -exec grep -l "spring" {} \;
```

Common file patterns: `Application.java`, `pom.xml`, `build.gradle`, `application.properties`, `application.yml`, `src/main/java/**/controller/`, `src/main/java/**/config/`.

---

## Critical Vulnerabilities

### 1. Spring Boot Actuator Exposed

Actuator endpoints expose health, metrics, environment variables, heap dumps, and can allow RCE via certain endpoints.

**Dangerous:**
```yaml
# application.yml - all actuator endpoints exposed without auth
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    env:
      enabled: true
    heapdump:
      enabled: true
    shutdown:
      enabled: true
```

```java
// No security on actuator endpoints
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/actuator/**").permitAll() // Dangerous
            .anyRequest().authenticated();
    }
}
```

**Safe:**
```yaml
# application.yml - minimal actuator exposure
management:
  endpoints:
    web:
      exposure:
        include: health,info
      base-path: /internal/monitor  # Non-default path
  endpoint:
    env:
      enabled: false
    heapdump:
      enabled: false
    shutdown:
      enabled: false
  server:
    port: 8081  # Separate port for actuator
```

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/actuator/**").hasRole("ADMIN")
            .anyRequest().authenticated();
    }
}
```

**Detection:**
```bash
grep -rn "actuator" --include="*.properties" --include="*.yml" --include="*.yaml" --include="*.java"
grep -rn "management\.endpoints\.web\.exposure\.include" --include="*.properties" --include="*.yml"
grep -rn "heapdump\|shutdown\|env\|beans\|mappings\|configprops" --include="*.properties" --include="*.yml"
grep -rn "permitAll.*actuator\|actuator.*permitAll" --include="*.java"
```

### 2. Spring Expression Language (SpEL) Injection

User input evaluated as SpEL allows arbitrary code execution.

**Dangerous:**
```java
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

@GetMapping("/eval")
public String evalExpression(@RequestParam String expr) {
    ExpressionParser parser = new SpelExpressionParser();
    // RCE: ?expr=T(java.lang.Runtime).getRuntime().exec('id')
    Expression exp = parser.parseExpression(expr);
    return exp.getValue().toString();
}

// SpEL in @Value with user data
@Value("#{${user.expression}}")
private String dynamicValue;

// SpEL in @PreAuthorize with user-controlled data
@PreAuthorize("#{#request.getParameter('role') == 'admin'}")
public void adminAction() { }
```

**Safe:**
```java
// Never pass user input to SpEL parser
// Use SimpleEvaluationContext to restrict capabilities
import org.springframework.expression.spel.support.SimpleEvaluationContext;

@GetMapping("/eval")
public String evalExpression(@RequestParam String expr) {
    ExpressionParser parser = new SpelExpressionParser();
    // Restricted context: no type references, no bean references
    EvaluationContext context = SimpleEvaluationContext
        .forReadOnlyDataBinding()
        .build();
    Expression exp = parser.parseExpression(expr);
    return exp.getValue(context, String.class);
}
```

**Detection:**
```bash
grep -rn "SpelExpressionParser\|parseExpression\|ExpressionParser" --include="*.java" --include="*.kt"
grep -rn "SimpleEvaluationContext\|StandardEvaluationContext" --include="*.java" --include="*.kt"
grep -rn "@Value.*#{\|@PreAuthorize.*#{\|@PostAuthorize.*#{" --include="*.java" --include="*.kt"
```

### 3. Deserialization Vulnerabilities

Deserializing untrusted data with ObjectInputStream or polymorphic Jackson.

**Dangerous:**
```java
// ObjectInputStream deserialization
@PostMapping("/import")
public String importData(@RequestBody byte[] data) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object obj = ois.readObject(); // RCE via gadget chains
    return obj.toString();
}

// Jackson polymorphic deserialization
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS) // Allows arbitrary class instantiation
public class Message {
    public Object payload;
}

// Default typing enabled globally
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // CVE-prone
```

**Safe:**
```java
// Use JSON instead of Java serialization
@PostMapping("/import")
public String importData(@RequestBody String data) {
    ObjectMapper mapper = new ObjectMapper();
    MyData obj = mapper.readValue(data, MyData.class); // Typed deserialization
    return obj.toString();
}

// If ObjectInputStream is required, use a filter
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
ois.setObjectInputFilter(filterInfo -> {
    if (filterInfo.serialClass() != null) {
        String className = filterInfo.serialClass().getName();
        if (ALLOWED_CLASSES.contains(className)) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.UNDECIDED;
});

// Jackson: use JsonTypeInfo.Id.NAME with explicit subtypes
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = TextMessage.class, name = "text"),
    @JsonSubTypes.Type(value = ImageMessage.class, name = "image")
})
public abstract class Message { }
```

**Detection:**
```bash
grep -rn "ObjectInputStream\|readObject()\|readUnshared()" --include="*.java" --include="*.kt"
grep -rn "enableDefaultTyping\|JsonTypeInfo.*Id\.CLASS\|JsonTypeInfo.*Id\.MINIMAL_CLASS" --include="*.java" --include="*.kt"
grep -rn "SerializationUtils\.deserialize\|XMLDecoder\|XStream" --include="*.java" --include="*.kt"
```

### 4. XML External Entity (XXE) Injection

Parsing XML without disabling external entities.

**Dangerous:**
```java
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

@PostMapping("/parse-xml")
public String parseXml(@RequestBody String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // No external entity protection
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(xml)));
    return doc.getDocumentElement().getTextContent();
}

// SAXParser without protection
SAXParserFactory factory = SAXParserFactory.newInstance();
SAXParser parser = factory.newSAXParser();
parser.parse(inputStream, handler);
```

**Safe:**
```java
@PostMapping("/parse-xml")
public String parseXml(@RequestBody String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // Disable external entities and DTDs
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setExpandEntityReferences(false);
    factory.setXIncludeAware(false);

    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(xml)));
    return doc.getDocumentElement().getTextContent();
}
```

**Detection:**
```bash
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|TransformerFactory\|SchemaFactory" --include="*.java" --include="*.kt"
grep -rn "disallow-doctype-decl\|external-general-entities\|external-parameter-entities" --include="*.java" --include="*.kt"
grep -rn "XMLReader\|SAXReader\|XStream\|XMLDecoder" --include="*.java" --include="*.kt"
```

---

## High Vulnerabilities

### 5. SQL Injection (JDBC and MyBatis)

**Dangerous:**
```java
// JDBC string concatenation
@GetMapping("/user")
public User getUser(@RequestParam String id) {
    String sql = "SELECT * FROM users WHERE id = " + id;
    return jdbcTemplate.queryForObject(sql, new UserRowMapper());
}

// MyBatis ${} interpolation (not parameterized)
// mapper.xml
// <select id="findUser" resultType="User">
//   SELECT * FROM users WHERE name = '${name}'
// </select>

// JPA native query with concatenation
@Query(value = "SELECT * FROM users WHERE email = '" + "#{#email}" + "'", nativeQuery = true)
User findByEmail(@Param("email") String email);
```

**Safe:**
```java
// JDBC parameterized
@GetMapping("/user")
public User getUser(@RequestParam String id) {
    String sql = "SELECT * FROM users WHERE id = ?";
    return jdbcTemplate.queryForObject(sql, new UserRowMapper(), id);
}

// MyBatis #{} parameterized
// <select id="findUser" resultType="User">
//   SELECT * FROM users WHERE name = #{name}
// </select>

// JPA with parameter binding
@Query("SELECT u FROM User u WHERE u.email = :email")
User findByEmail(@Param("email") String email);

// Spring Data JPA derived query (safest)
User findByEmail(String email);
```

**Detection:**
```bash
grep -rn "jdbcTemplate.*+\|\"SELECT.*+\|\"INSERT.*+\|\"UPDATE.*+\|\"DELETE.*+" --include="*.java" --include="*.kt"
grep -rn "\${" --include="*.xml" | grep -i "select\|insert\|update\|delete"
grep -rn "nativeQuery.*true" --include="*.java" --include="*.kt"
grep -rn "createQuery(.*+\|createNativeQuery(.*+" --include="*.java" --include="*.kt"
```

### 6. Server-Side Request Forgery (SSRF)

**Dangerous:**
```java
@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) throws Exception {
    // No URL validation
    URL target = new URL(url);
    HttpURLConnection conn = (HttpURLConnection) target.openConnection();
    BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
    return reader.lines().collect(Collectors.joining("\n"));
}

// RestTemplate with user URL
@GetMapping("/proxy")
public ResponseEntity<String> proxy(@RequestParam String url) {
    return restTemplate.getForEntity(url, String.class);
}
```

**Safe:**
```java
import java.net.InetAddress;

private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "cdn.example.com");

@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) throws Exception {
    URL target = new URL(url);
    // Validate scheme
    if (!Set.of("http", "https").contains(target.getProtocol())) {
        throw new SecurityException("Invalid protocol");
    }
    // Validate host
    if (!ALLOWED_HOSTS.contains(target.getHost())) {
        InetAddress addr = InetAddress.getByName(target.getHost());
        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
            throw new SecurityException("Internal addresses not allowed");
        }
    }
    HttpURLConnection conn = (HttpURLConnection) target.openConnection();
    conn.setConnectTimeout(5000);
    conn.setInstanceFollowRedirects(false);
    return new String(conn.getInputStream().readAllBytes());
}
```

**Detection:**
```bash
grep -rn "new URL(.*request\|new URL(.*param\|new URL(.*@RequestParam" --include="*.java" --include="*.kt"
grep -rn "restTemplate.*getFor\|restTemplate.*postFor\|restTemplate.*exchange" --include="*.java" --include="*.kt" | grep -i "param\|request\|input"
grep -rn "WebClient.*uri(.*request\|HttpClient.*send(.*request" --include="*.java" --include="*.kt"
```

### 7. Path Traversal

**Dangerous:**
```java
@GetMapping("/download")
public ResponseEntity<Resource> download(@RequestParam String filename) {
    // Attacker: ?filename=../../../etc/passwd
    Path path = Paths.get("/uploads/" + filename);
    Resource resource = new FileSystemResource(path.toFile());
    return ResponseEntity.ok().body(resource);
}
```

**Safe:**
```java
private static final Path UPLOAD_DIR = Paths.get("/uploads").toAbsolutePath().normalize();

@GetMapping("/download")
public ResponseEntity<Resource> download(@RequestParam String filename) {
    Path path = UPLOAD_DIR.resolve(filename).normalize();
    // Verify path is within upload directory
    if (!path.startsWith(UPLOAD_DIR)) {
        throw new SecurityException("Access denied");
    }
    if (!Files.exists(path)) {
        return ResponseEntity.notFound().build();
    }
    Resource resource = new FileSystemResource(path.toFile());
    return ResponseEntity.ok().body(resource);
}
```

**Detection:**
```bash
grep -rn "Paths\.get(.*request\|Paths\.get(.*param\|new File(.*request\|new File(.*param" --include="*.java" --include="*.kt"
grep -rn "FileSystemResource\|PathResource\|FileInputStream" --include="*.java" --include="*.kt" | grep -i "param\|request"
grep -rn "normalize()\|toAbsolutePath()\|startsWith(" --include="*.java" --include="*.kt"
```

### 8. Mass Assignment (@RequestBody Without DTO)

**Dangerous:**
```java
// Entity directly bound from request
@PostMapping("/user")
public User createUser(@RequestBody User user) {
    // Attacker can set: {"username":"test","role":"ADMIN","active":true}
    return userRepository.save(user);
}

// Map binding
@PutMapping("/settings")
public void updateSettings(@RequestBody Map<String, Object> settings) {
    settings.forEach((key, value) -> settingsService.set(key, value));
}
```

**Safe:**
```java
// Use a DTO with only allowed fields
public class CreateUserDTO {
    @NotBlank
    private String username;
    @Email
    private String email;
    @Size(min = 8)
    private String password;
    // No role, no active, no admin fields
}

@PostMapping("/user")
public User createUser(@Valid @RequestBody CreateUserDTO dto) {
    User user = new User();
    user.setUsername(dto.getUsername());
    user.setEmail(dto.getEmail());
    user.setPassword(passwordEncoder.encode(dto.getPassword()));
    user.setRole(Role.USER); // Explicitly set defaults
    return userRepository.save(user);
}
```

**Detection:**
```bash
grep -rn "@RequestBody.*Entity\|@RequestBody.*Model" --include="*.java" --include="*.kt"
grep -rn "@RequestBody\s\+Map<" --include="*.java" --include="*.kt"
grep -rn "@ModelAttribute" --include="*.java" --include="*.kt"
# Look for entities directly in controller method params
grep -rn "repository\.save(.*@RequestBody\|\.save(.*request" --include="*.java" --include="*.kt"
```

### 9. Insecure CORS Configuration

**Dangerous:**
```java
@CrossOrigin(origins = "*")
@RestController
public class ApiController {
    // All endpoints allow any origin
}

// Global CORS config
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
            .allowedOrigins("*")
            .allowCredentials(true); // Wildcard + credentials
    }
}
```

**Safe:**
```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("https://myapp.com", "https://admin.myapp.com")
            .allowedMethods("GET", "POST", "PUT", "DELETE")
            .allowedHeaders("Authorization", "Content-Type")
            .allowCredentials(true)
            .maxAge(3600);
    }
}
```

**Detection:**
```bash
grep -rn "@CrossOrigin" --include="*.java" --include="*.kt"
grep -rn "allowedOrigins.*\*\|CorsRegistry\|addCorsMappings" --include="*.java" --include="*.kt"
grep -rn "allowCredentials.*true" --include="*.java" --include="*.kt"
```

---

## Medium Vulnerabilities

### 10. Missing CSRF Protection

**Dangerous:**
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable() // CSRF disabled entirely
            .authorizeRequests()
            .anyRequest().authenticated();
    }
}
```

**Safe:**
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .authorizeRequests()
            .anyRequest().authenticated();
    }
}
// For stateless REST APIs with JWT/token auth, disabling CSRF is acceptable
```

**Detection:**
```bash
grep -rn "csrf()\.disable\|csrf\.disable" --include="*.java" --include="*.kt"
grep -rn "CsrfTokenRepository\|CookieCsrfTokenRepository" --include="*.java" --include="*.kt"
```

### 11. Verbose Error Messages in Production

**Dangerous:**
```yaml
# application.yml
server:
  error:
    include-stacktrace: always
    include-message: always
    include-binding-errors: always
    include-exception: true
```

```java
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleError(Exception ex) {
    return ResponseEntity.status(500).body(ex.getMessage() + "\n" + Arrays.toString(ex.getStackTrace()));
}
```

**Safe:**
```yaml
# application.yml
server:
  error:
    include-stacktrace: never
    include-message: never
    include-binding-errors: never
    include-exception: false
```

```java
@ExceptionHandler(Exception.class)
public ResponseEntity<Map<String, String>> handleError(Exception ex) {
    log.error("Internal error", ex); // Log details server-side
    return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
}
```

**Detection:**
```bash
grep -rn "include-stacktrace\|include-message\|include-exception\|include-binding-errors" --include="*.properties" --include="*.yml" --include="*.yaml"
grep -rn "getStackTrace\|printStackTrace\|getMessage" --include="*.java" --include="*.kt" | grep -i "response\|return\|body"
```

### 12. Swagger/OpenAPI Exposed in Production

**Dangerous:**
```yaml
# Swagger UI accessible in production
# No profile-based gating
springdoc:
  swagger-ui:
    path: /swagger-ui.html
    enabled: true
```

**Safe:**
```yaml
# application-prod.yml
springdoc:
  swagger-ui:
    enabled: false
  api-docs:
    enabled: false
```

```java
@Configuration
@Profile("!prod")
public class SwaggerConfig {
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI().info(new Info().title("API").version("1.0"));
    }
}
```

**Detection:**
```bash
grep -rn "swagger\|springdoc\|springfox\|api-docs" --include="*.properties" --include="*.yml" --include="*.yaml"
grep -rn "@Profile.*prod\|@ConditionalOn" --include="*.java" --include="*.kt" | grep -i "swagger\|springdoc"
grep -rn "swagger-ui\|Docket\|OpenAPI" --include="*.java" --include="*.kt"
```

---

## Framework Extension Security

### 13. Spring Security Misconfiguration

**Dangerous:**
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/**").permitAll()  // All API endpoints public
            .antMatchers("/admin/**").authenticated()
            .anyRequest().permitAll();  // Default allow
    }
}

// Weak password encoding
@Bean
public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance(); // Plaintext passwords
}
```

**Safe:**
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/public/**", "/health").permitAll()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()  // Default deny
            .and()
            .formLogin()
            .and()
            .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
```

**Detection:**
```bash
grep -rn "permitAll\|hasRole\|hasAuthority\|authenticated()" --include="*.java" --include="*.kt"
grep -rn "NoOpPasswordEncoder\|PlaintextPasswordEncoder\|MD5PasswordEncoder" --include="*.java" --include="*.kt"
grep -rn "WebSecurityConfigurerAdapter\|SecurityFilterChain" --include="*.java" --include="*.kt"
```

### 14. @PreAuthorize Bypass

**Dangerous:**
```java
// Missing @PreAuthorize on sensitive methods
@Service
public class AdminService {
    public void deleteAllUsers() {
        userRepository.deleteAll(); // No authorization check
    }
}

// @PreAuthorize not enforced (missing @EnableGlobalMethodSecurity)
@PreAuthorize("hasRole('ADMIN')")
public void adminAction() { }  // Annotation has no effect without enable
```

**Safe:**
```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration { }

@Service
public class AdminService {
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteAllUsers() {
        userRepository.deleteAll();
    }
}
```

**Detection:**
```bash
grep -rn "@PreAuthorize\|@PostAuthorize\|@Secured\|@RolesAllowed" --include="*.java" --include="*.kt"
grep -rn "@EnableGlobalMethodSecurity\|@EnableMethodSecurity" --include="*.java" --include="*.kt"
grep -rn "prePostEnabled\|securedEnabled\|jsr250Enabled" --include="*.java" --include="*.kt"
```

### 15. OAuth2 Misconfiguration

**Dangerous:**
```yaml
# Weak OAuth2 configuration
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-secret: hardcoded-secret-here
```

```java
// Not validating OAuth2 state parameter
// Not validating redirect URI
// Accepting any scope
```

**Safe:**
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${OAUTH_CLIENT_ID}
            client-secret: ${OAUTH_CLIENT_SECRET}
            scope: openid,profile,email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
```

**Detection:**
```bash
grep -rn "client-secret\|clientSecret" --include="*.properties" --include="*.yml" --include="*.yaml" | grep -v "\${"
grep -rn "oauth2\|OAuth2" --include="*.java" --include="*.kt" --include="*.properties" --include="*.yml"
grep -rn "redirect-uri\|redirectUri" --include="*.properties" --include="*.yml" --include="*.java"
```

---

## Detection Commands

```bash
# Full Spring Boot security scan
echo "=== Actuator ==="
grep -rn "actuator\|management\.endpoints" --include="*.properties" --include="*.yml" --include="*.yaml"

echo "=== SpEL Injection ==="
grep -rn "SpelExpressionParser\|parseExpression" --include="*.java" --include="*.kt"

echo "=== Deserialization ==="
grep -rn "ObjectInputStream\|readObject\|enableDefaultTyping\|JsonTypeInfo.*CLASS" --include="*.java" --include="*.kt"

echo "=== XXE ==="
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory" --include="*.java" --include="*.kt"
grep -rn "disallow-doctype-decl" --include="*.java" --include="*.kt"

echo "=== SQL Injection ==="
grep -rn "\${" --include="*.xml" | grep -i "select\|insert\|update\|delete"
grep -rn "nativeQuery.*true" --include="*.java" --include="*.kt"
grep -rn "jdbcTemplate.*+\|\"SELECT.*+" --include="*.java" --include="*.kt"

echo "=== SSRF ==="
grep -rn "new URL(\|restTemplate\.\|WebClient\.\|HttpClient\." --include="*.java" --include="*.kt" | grep -i "param\|request"

echo "=== Path Traversal ==="
grep -rn "Paths\.get(.*param\|new File(.*param" --include="*.java" --include="*.kt"

echo "=== Mass Assignment ==="
grep -rn "@RequestBody" --include="*.java" --include="*.kt"

echo "=== CORS ==="
grep -rn "@CrossOrigin\|allowedOrigins\|CorsRegistry" --include="*.java" --include="*.kt"

echo "=== Security Config ==="
grep -rn "csrf.*disable\|permitAll\|NoOpPasswordEncoder" --include="*.java" --include="*.kt"

echo "=== Swagger ==="
grep -rn "swagger\|springdoc\|api-docs" --include="*.properties" --include="*.yml"
```

---

## Audit Checklist

- [ ] Actuator endpoints restricted (only `health`/`info`), behind authentication, on separate port
- [ ] No `SpelExpressionParser` with user input; if used, `SimpleEvaluationContext` applied
- [ ] No `ObjectInputStream.readObject()` with untrusted data; Jackson `defaultTyping` disabled
- [ ] XML parsing disables external entities (`disallow-doctype-decl`)
- [ ] All SQL uses parameterized queries; MyBatis uses `#{}` not `${}`
- [ ] SSRF mitigated: URL validation, private IP blocking, no open redirects
- [ ] Path traversal prevented: resolved paths checked against base directory
- [ ] DTOs used for `@RequestBody` (no entity classes directly)
- [ ] `@CrossOrigin` specifies explicit origins (no `*` with credentials)
- [ ] CSRF enabled for browser-facing endpoints
- [ ] Error responses do not include stack traces or internal details
- [ ] Swagger/OpenAPI disabled in production profile
- [ ] Spring Security default-deny policy (`anyRequest().authenticated()`)
- [ ] `@EnableGlobalMethodSecurity(prePostEnabled = true)` configured
- [ ] BCryptPasswordEncoder (or Argon2) used for password hashing
- [ ] OAuth2 secrets from environment variables, redirect URIs validated
- [ ] `server.error.include-stacktrace=never` in production
- [ ] `management.endpoints.web.exposure.include` is minimal
