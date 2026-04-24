# Rust Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers Axum, Actix Web, Rocket, async workers, FFI boundaries, and security-sensitive systems code.

---

## Language-Specific Hotspots

- `unsafe`, FFI, `transmute`, and raw pointer boundaries
- `Command::new("sh").arg("-c")`, `format!`-built SQL, and template `safe` bypasses
- `serde`-driven request binding into privileged structs
- Middleware ordering and extractor-based authorization gaps in Axum / Actix

---

## C1: Injection

### Key Questions
- Are SQL queries built with `format!`, `sql_query`, or raw strings instead of parameters?
- Do any commands go through `sh -c`, `cmd /c`, or user-selected binaries?
- Are template engines using `|safe`, raw HTML types, or user-controlled templates?
- Can regex, shell, or deserialization inputs trigger DoS or arbitrary behavior?

### Dangerous Patterns

```rust
let sql = format!("SELECT * FROM users WHERE email = '{}'", email);
sqlx::query(&sql).fetch_one(&pool).await?;

Command::new("sh")
    .arg("-c")
    .arg(format!("tar -xf {}", archive))
    .status()?;

let body = tera.render_str(user_template, &ctx)?;
```

### Safe Alternatives

```rust
sqlx::query("SELECT * FROM users WHERE email = $1")
    .bind(email)
    .fetch_one(&pool)
    .await?;

Command::new("tar").arg("-xf").arg(validated_archive).status()?;
```

### Grep Detection Patterns

```bash
grep -rn 'format!.*SELECT|format!.*INSERT|format!.*UPDATE|format!.*DELETE|sql_query\\(' --include="*.rs"
grep -rn 'Command::new\\(\"sh\"\\)|Command::new\\(\"bash\"\\)|Command::new\\(\"cmd\"\\)' --include="*.rs"
grep -rn 'render_str\\(|Template::new\\(|\\|safe\\b|Html\\(' --include="*.rs"
grep -rn 'Regex::new\\(|serde_yaml|toml::from_str|bincode::deserialize' --include="*.rs"
```

---

## C2: Authentication

### Key Questions
- Is `jsonwebtoken::dangerous_insecure_decode` absent from production paths?
- Are JWT validation rules explicit for issuer, audience, expiry, and algorithm?
- Are passwords hashed with `argon2` / `bcrypt`, not plain hashes?
- Are session cookies signed, scoped, and rotated on auth changes?

### Detection

```bash
grep -rn 'dangerous_insecure_decode|Validation::default|validate_exp|set_audience|set_issuer' --include="*.rs"
grep -rn 'argon2|bcrypt|sha2|md5|pbkdf2' --include="*.rs"
grep -rn 'Cookie::build|tower_sessions|actix_session|SameSite|http_only|secure' --include="*.rs"
```

---

## C3: Authorization

### Key Questions
- Are resource queries filtered by `user_id` / `tenant_id`, not just path IDs?
- Is auth middleware layered before handlers for all routes and routers?
- Are admin or internal routes in separate route trees with explicit policies?
- Do websocket, gRPC, and background-job entry points enforce the same authorization model?

### Detection

```bash
grep -rn 'Path<|Path\\(|Query<|Json<' --include="*.rs"
grep -rn 'route_layer\\(|layer\\(|middleware::from_fn|wrap\\(' --include="*.rs"
grep -rn 'SELECT .* WHERE id = \\$1|find_by_id|get\\(' --include="*.rs"
grep -rn 'admin|is_admin|role|tenant_id|owner_id' --include="*.rs"
```

---

## C4: Mass Assignment

### Key Questions
- Do `Deserialize` structs expose fields the client should never control?
- Are PATCH/PUT handlers merging arbitrary JSON maps into models?
- Can `serde(flatten)` or defaulted fields hide privilege changes?
- Do ORM update helpers write every field from a bound struct?

### Dangerous Patterns

```rust
#[derive(Deserialize)]
struct UpdateUser {
    name: String,
    role: String,
    credit_limit: i64,
}

let req: UpdateUser = payload.into_inner();
sqlx::query("UPDATE users SET name = $1, role = $2, credit_limit = $3 WHERE id = $4")
    .bind(req.name)
    .bind(req.role)
    .bind(req.credit_limit)
    .bind(user_id);
```

### Detection

```bash
grep -rn '#\\[derive\\(Deserialize\\)\\]|serde\\(flatten\\)|HashMap<String, Value>|Map<String, Value>' --include="*.rs"
grep -rn 'role|admin|tenant_id|balance|credit_limit|permissions' --include="*.rs"
```

---

## C5: Data Exposure

### Key Questions
- Are `Debug` / `Serialize` derives leaking secrets, tokens, or internal metadata?
- Do error responses expose SQL, filesystem paths, backtraces, or panic messages?
- Are signed URLs, presigned object keys, or internal service endpoints returned too broadly?
- Are diagnostics endpoints or tracing subscribers exposing sensitive state?

### Detection

```bash
grep -rn 'derive\\(.*Debug|derive\\(.*Serialize|panic!|unwrap\\(|expect\\(' --include="*.rs"
grep -rn 'backtrace|RUST_BACKTRACE|tracing_subscriber|tower_http::trace' --include="*.rs"
grep -rn 'token|secret|password|private_key|authorization' --include="*.rs"
```

---

## C6: Security Misconfiguration

### Key Questions
- Is CORS broad or combined incorrectly with credentials?
- Are TLS clients configured to accept invalid certs or skip hostname validation?
- Are debug logs, panic hooks, or verbose errors enabled in production?
- Are feature flags or environment defaults enabling insecure code paths?

### Detection

```bash
grep -rn 'allow_origin\\(Any\\)|allow_credentials\\(true\\)|CorsLayer' --include="*.rs"
grep -rn 'danger_accept_invalid_certs|danger_accept_invalid_hostnames' --include="*.rs"
grep -rn 'cfg\\(debug_assertions\\)|RUST_LOG|set_hook|tracing::level_filters::LevelFilter::DEBUG' --include="*.rs"
```

---

## C7: XSS

### Key Questions
- Are Askama, Tera, Handlebars, or Maud templates bypassing escaping?
- Is user-controlled HTML rendered through raw HTML wrappers?
- Are values embedded into JavaScript or URL contexts without context-aware encoding?
- Can markdown or HTML content bypass sanitization before display?

### Detection

```bash
grep -rn '\\|safe\\b|safe_html|Html\\(|PreEscaped\\(|dangerously_set_inner_html' --include="*.rs" --include="*.html"
grep -rn 'render_str\\(|markdown|pulldown_cmark|comrak' --include="*.rs"
```

---

## C8: Dependencies

### Review Checklist
- Run `cargo audit` and inspect yanked crates.
- Review unsafe-heavy crates, parser crates, image libraries, and TLS stacks.
- Verify `Cargo.lock` is committed for applications.
- Check optional features that expand attack surface, especially admin or test helpers.

### Detection

```bash
cargo audit
grep -rn 'default-features = false|features = \\[' Cargo.toml
test -f Cargo.lock && echo "Cargo.lock present"
```

---

## C9: Cryptography

### Key Questions
- Are secrets generated with `OsRng` / `getrandom`, not `fastrand` or `SmallRng`?
- Are passwords hashed with `argon2` / `bcrypt` using reasonable parameters?
- Are HMAC and signature checks constant-time?
- Are keys, nonces, and IVs random, unique, and never hardcoded?

### Detection

```bash
grep -rn 'fastrand|SmallRng|thread_rng\\(|OsRng|getrandom|subtle' --include="*.rs"
grep -rn 'argon2|bcrypt|ring::hmac|hmac::|aes|chacha20|pbkdf2' --include="*.rs"
grep -rn 'const .*KEY|static .*KEY|include_str!.*pem' --include="*.rs"
```

---

## C10: SSRF

### Key Questions
- Can user input reach `reqwest`, `hyper`, `ureq`, `awc`, or webhook clients?
- Are resolved IPs checked for loopback, link-local, RFC1918, and metadata networks?
- Are redirects and alternate schemes restricted?
- Are cached DNS answers or follow-up fetches revalidated?

### Detection

```bash
grep -rn 'reqwest::|Client::new\\(|hyper::Client|ureq::|awc::Client' --include="*.rs"
grep -rn 'redirect|Policy::|resolve|lookup_ip|ToSocketAddrs|169\\.254\\.169\\.254|127\\.0\\.0\\.1|::1' --include="*.rs"
```

---

## C11: Logging & Monitoring

### Key Questions
- Are secrets logged in `tracing` fields or request spans?
- Can user-controlled strings inject fake log structure or newlines?
- Are auth and permission events logged distinctly from ordinary failures?
- Do panic and error reporters capture request bodies or headers unsafely?

### Detection

```bash
grep -rn 'tracing::|info!\\(|warn!\\(|error!\\(|instrument\\(' --include="*.rs"
grep -rn 'authorization|cookie|token|password|secret|body' --include="*.rs"
```

---

## C12: Infrastructure & Deployment

### Key Questions
- Do containers run as non-root with minimal capabilities?
- Are FFI dependencies, OpenSSL, and system libraries patched and pinned?
- Are admin/debug features excluded from release builds?
- Are runtime environment variables, config files, and certificates mounted safely?

### Detection

```bash
find . -name "Dockerfile" -o -name "docker-compose.yml" -o -name ".github"
grep -rn 'USER root|RUST_LOG=debug|cargo run|openssl|libssl' --include="Dockerfile" --include="*.yml" --include="*.sh"
```
