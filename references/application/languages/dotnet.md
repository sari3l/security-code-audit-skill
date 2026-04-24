# .NET / C# Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers ASP.NET Core, minimal APIs, MVC, SignalR, workers, EF Core, Dapper, and common .NET service patterns.

---

## Language-Specific Hotspots

- `FromSqlRaw`, `ExecuteSqlRaw`, Dapper raw SQL, and `Process.Start`
- DTO-to-entity binding and `TryUpdateModelAsync` mass assignment
- Middleware ordering: `UseAuthentication`, `UseAuthorization`, endpoint mapping
- `HttpClient` SSRF, `TypeNameHandling`, file-path confusion, and broad CORS

---

## C1: Injection

### Key Questions
- Are SQL queries built with string interpolation or raw SQL helpers?
- Can user input reach `Process.Start`, PowerShell, or shell-command strings?
- Are LDAP, XPath, JSON polymorphism, or XML parsers fed untrusted data?
- Are table or column names controlled dynamically without allowlists?

### Dangerous Patterns

```csharp
var sql = $"SELECT * FROM Users WHERE Email = '{email}'";
await context.Users.FromSqlRaw(sql).ToListAsync();

Process.Start("cmd.exe", "/c ping " + host);

var searcher = new DirectorySearcher();
searcher.Filter = "(&(uid=" + user + ")(objectClass=person))";
```

### Safe Alternatives

```csharp
await context.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Email = {email}")
    .ToListAsync();

using var cmd = new SqlCommand("SELECT * FROM Users WHERE Email = @email", conn);
cmd.Parameters.AddWithValue("@email", email);

var psi = new ProcessStartInfo("ping") {
    ArgumentList = { "-n", "1", validatedHost },
    UseShellExecute = false,
};
Process.Start(psi);
```

### Grep Detection Patterns

```bash
grep -rn 'FromSqlRaw|ExecuteSqlRaw|SqlCommand\\(|Query\\(|Execute\\(' --include="*.cs"
grep -rn 'Process\\.Start|ProcessStartInfo|cmd\\.exe|powershell' --include="*.cs"
grep -rn 'DirectorySearcher|XPath|XmlDocument|XDocument|JsonSerializerSettings|TypeNameHandling' --include="*.cs"
```

---

## C2: Authentication

### Key Questions
- Are JWTs validated with full `TokenValidationParameters`?
- Is `UseAuthentication()` registered before `UseAuthorization()` and endpoint mapping?
- Are cookies configured with `Secure`, `HttpOnly`, `SameSite`, and rotation on auth changes?
- Are password reset, OTP, and magic-link flows time-limited and rate-limited?

### Detection

```bash
grep -rn 'AddAuthentication|AddJwtBearer|TokenValidationParameters|ValidateIssuerSigningKey|ValidateIssuer|ValidateAudience' --include="*.cs"
grep -rn 'UseAuthentication|UseAuthorization|MapControllers|MapGroup|MapGet|MapPost' --include="*.cs"
grep -rn 'CookieAuthenticationOptions|SameSite|HttpOnly|SecurePolicy' --include="*.cs"
```

---

## C3: Authorization

### Key Questions
- Are resource lookups filtered by current user or tenant, not just IDs?
- Are `[Authorize]`, roles, policies, and resource handlers applied consistently?
- Are SignalR hubs, minimal APIs, and background jobs protected separately from MVC controllers?
- Can `IgnoreQueryFilters()` or direct repository calls bypass tenant isolation?

### Detection

```bash
grep -rn '\\[Authorize|RequireAuthorization|AllowAnonymous|IAuthorizationHandler|AuthorizeAsync' --include="*.cs"
grep -rn 'FindAsync\\(|FirstOrDefaultAsync\\(|SingleOrDefaultAsync\\(' --include="*.cs"
grep -rn 'IgnoreQueryFilters\\(|tenantId|OwnerId|UserId|IsInRole' --include="*.cs"
```

---

## C4: Mass Assignment

### Key Questions
- Are entities bound directly from request bodies instead of DTOs?
- Does `TryUpdateModelAsync` or automapper copy privileged fields?
- Can payloads set `Role`, `IsAdmin`, `OwnerId`, `TenantId`, `Balance`, or approval flags?
- Are PATCH endpoints validating which JSON Patch operations are allowed?

### Dangerous Patterns

```csharp
[HttpPost]
public async Task<IActionResult> Update([FromBody] User user) {
    _db.Update(user);
    await _db.SaveChangesAsync();
    return Ok();
}

await TryUpdateModelAsync(user);
```

### Detection

```bash
grep -rn '\\[FromBody\\].*Entity|TryUpdateModelAsync|JsonPatchDocument|Map<.*Entity>|_mapper.Map' --include="*.cs"
grep -rn 'Role|IsAdmin|OwnerId|TenantId|Balance|CreditLimit|Approved' --include="*.cs"
```

---

## C5: Data Exposure

### Key Questions
- Do serializers, DTOs, or logs expose tokens, hashes, internal IDs, or connection strings?
- Are developer exception pages, stack traces, or detailed validation errors enabled in production?
- Are Swagger, health checks, or metadata endpoints overexposed?
- Are data-protection keys, secrets, or appsettings committed or broadly readable?

### Detection

```bash
grep -rn 'UseDeveloperExceptionPage|IncludeExceptionDetails|EnableSensitiveDataLogging|AddSwaggerGen|MapHealthChecks' --include="*.cs"
grep -rn 'password|token|secret|connectionstring|privatekey' --include="*.cs" --include="*.json"
grep -rn 'JsonIgnore|IgnoreDataMember|DataProtection' --include="*.cs"
```

---

## C6: Security Misconfiguration

### Key Questions
- Are CORS, CSRF, cookies, and forwarded headers configured safely?
- Are development-only services, H2-style consoles, or internal admin tools reachable?
- Are TLS validation or certificate pinning settings weakened?
- Are default credentials or permissive sample settings shipped to production?

### Detection

```bash
grep -rn 'AllowAnyOrigin|AllowCredentials|SetIsOriginAllowed|Antiforgery|IgnoreAntiforgeryToken|ForwardedHeaders' --include="*.cs"
grep -rn 'DangerousAcceptAnyServerCertificateValidator|ServerCertificateCustomValidationCallback' --include="*.cs"
grep -rn 'appsettings.Development|Development|UseDeveloperExceptionPage' --include="*.cs" --include="*.json"
```

---

## C7: XSS

### Key Questions
- Are Razor, Blazor, or MVC views bypassing encoding with `Html.Raw`?
- Is untrusted HTML rendered into rich text, emails, or WebView-like controls?
- Are values embedded into script or attribute contexts without context-aware encoding?
- Are markdown and file-upload rendering paths sanitized?

### Detection

```bash
grep -rn 'Html\\.Raw|MarkupString|AddContent\\(|WriteLiteral\\(' --include="*.cshtml" --include="*.razor" --include="*.cs"
grep -rn 'WebView|BlazorWebView|markdown|Ganss.Xss|sanitize' --include="*.cs"
```

---

## C8: Dependencies

### Review Checklist
- Run NuGet / SCA tooling and inspect transitive packages.
- Review `Newtonsoft.Json`, `System.Text.Json`, image parsers, markdown libraries, auth handlers, and file processors.
- Flag unsupported .NET runtimes and SDKs.
- Check self-hosted admin middleware and diagnostics packages.

### Detection

```bash
find . -name "*.csproj" -o -name "*.props" -o -name "packages.lock.json" -o -name "NuGet.config"
grep -rn 'PackageReference|TargetFramework|Newtonsoft.Json|Microsoft.AspNetCore|Serilog|ImageSharp' --include="*.csproj" --include="*.props"
```

---

## C9: Cryptography

### Key Questions
- Are tokens and secrets generated with `RandomNumberGenerator`, not `Random`?
- Are passwords hashed with ASP.NET Identity or PBKDF2/bcrypt/argon2 rather than raw hashes?
- Are keys and IVs sourced securely and rotated?
- Are signature and secret comparisons constant-time?

### Detection

```bash
grep -rn 'RandomNumberGenerator|RNGCryptoServiceProvider|Random\\(|PasswordHasher|Rfc2898DeriveBytes|SHA1|MD5|Aes' --include="*.cs"
grep -rn 'FixedTimeEquals|CryptographicOperations|machineKey|DataProtection' --include="*.cs"
```

---

## C10: SSRF

### Key Questions
- Can user-controlled URLs reach `HttpClient`, `WebClient`, `HttpWebRequest`, or import features?
- Are redirects, localhost, metadata IPs, and DNS rebinding mitigated?
- Are alternate encodings, IPv6 literals, and credential-bearing URLs handled safely?
- Are outbound HTTP clients separated by trust boundary?

### Detection

```bash
grep -rn 'HttpClient|WebClient|HttpWebRequest|GetAsync\\(|PostAsync\\(|SendAsync\\(' --include="*.cs"
grep -rn 'AllowAutoRedirect|ServerCertificateCustomValidationCallback|169\\.254\\.169\\.254|127\\.0\\.0\\.1|localhost|::1' --include="*.cs"
```

---

## C11: Logging & Monitoring

### Key Questions
- Are auth headers, tokens, or request bodies logged?
- Can user input forge structured log fields or newline-delimited logs?
- Are auth failures, role changes, and destructive actions audited distinctly?
- Do APM and error reporters capture sensitive request context?

### Detection

```bash
grep -rn 'ILogger|LogInformation|LogWarning|LogError|Serilog|NLog|Sentry' --include="*.cs"
grep -rn 'Authorization|password|token|secret|cookie|Request\\.Body' --include="*.cs"
```

---

## C12: Infrastructure & Deployment

### Key Questions
- Do containers and services run as non-root with least privilege?
- Are Data Protection keys, certificates, and app secrets mounted safely?
- Are Kestrel, reverse proxies, and static file hosting configured with restrictive defaults?
- Are CI/CD pipelines and publish profiles leaking secrets?

### Detection

```bash
find . -name "Dockerfile" -o -name "docker-compose.yml" -o -name "*.pubxml" -o -name "*.service"
grep -rn 'USER root|ASPNETCORE_ENVIRONMENT=Development|DataProtection-Keys|UseStaticFiles|--privileged' --include="Dockerfile" --include="*.yml" --include="*.cs" --include="*.pubxml"
```
