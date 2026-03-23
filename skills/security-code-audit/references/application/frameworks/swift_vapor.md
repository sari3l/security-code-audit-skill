# Vapor Security Reference

## Identification Features

```bash
grep -r 'import Vapor' --include="*.swift"
grep -r 'RoutesBuilder\|Application\|Request' --include="*.swift"
test -f Package.swift && grep -n "vapor" Package.swift
```

Common file patterns: `Sources/App/routes.swift`, `Controllers/`, `Models/`, `Migrations/`, `configure.swift`.

---

## High-Risk Framework Surfaces

### 1. `Content` Binding

- request bodies decoded directly into Fluent models
- update DTOs exposing `role`, `ownerID`, `isAdmin`, or billing fields

### 2. Route Group Coverage

- auth middleware applied to some groups but not nested route trees
- admin routes separated by path only, not by middleware

### 3. Leaf and HTML Rendering

- raw HTML fed into Leaf or `Response` bodies
- untrusted markdown or rich text rendered as trusted HTML

### 4. File and URL Helpers

- `req.fileio.streamFile` or path joins using user-controlled names
- webhook, import, or preview routes fetching user-supplied URLs

---

## Detection Commands

```bash
grep -rn 'Content\\s*{|req\\.content\\.decode|Model, Content' --include="*.swift"
grep -rn 'grouped\\(|middleware\\(|RoutesBuilder' --include="*.swift"
grep -rn 'Leaf|render\\(|loadHTMLString|Response\\(body:' --include="*.swift"
grep -rn 'fileio|streamFile|URLSession|HTTPClient|Client\\.' --include="*.swift"
```

---

## Audit Questions

- Are request DTOs separate from Fluent models?
- Do grouped routes inherit auth and role middleware exactly as intended?
- Is rendered HTML always either escaped or sanitized?
- Can file and URL helpers reach paths or hosts beyond the intended boundary?
