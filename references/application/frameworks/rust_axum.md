# Axum Security Reference

## Identification Features

```bash
grep -r 'axum =' Cargo.toml
grep -r 'Router::new\|route_layer\|Json<' --include="*.rs"
grep -r 'State<\|Extension<\|Path<' --include="*.rs"
```

Common file patterns: `src/main.rs`, `routes/`, `handlers/`, `middleware/`, `state.rs`.

---

## High-Risk Framework Surfaces

### 1. Extractor Trust

- `Json<T>` decoding into over-broad structs
- `Path` and `Query` values reused directly in SQL, files, or outbound requests
- `Option<Extension<User>>` or similar soft-auth patterns on sensitive routes

### 2. Tower Layer Coverage

- auth layers applied to some routers but not nested routers or merged subtrees
- admin routes grouped incorrectly before protection

### 3. SQL and State Helpers

- `sqlx::query(&format!(...))`
- state objects exposing raw DB or file helpers without policy enforcement

### 4. File and HTTP Helpers

- download handlers using user-controlled paths
- SSRF through `reqwest` or webhook utilities called from handlers

---

## Detection Commands

```bash
grep -rn 'Router::new|merge\\(|nest\\(|route_layer\\(|layer\\(' --include="*.rs"
grep -rn 'Json<|Path<|Query<|Extension<|State<' --include="*.rs"
grep -rn 'sqlx::query\\(&format!|format!.*SELECT|reqwest::|tokio::fs::|std::fs::' --include="*.rs"
```

---

## Audit Questions

- Are nested routers protected as tightly as top-level routers?
- Do extractors decode into DTOs or privileged persistence structs?
- Are path and query inputs validated before hitting SQL, files, or URLs?
- Does shared state centralize authorization or accidentally bypass it?
