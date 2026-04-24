# Gin Security Reference

## Identification Features

```bash
grep -r 'github.com/gin-gonic/gin' --include="*.go"
grep -r 'gin\.Default()\|gin\.New()' --include="*.go"
grep -r 'ShouldBindJSON\|BindJSON\|c\.Param\|c\.Query' --include="*.go"
```

Common file patterns: `cmd/`, `internal/handler/`, `middleware/`, `router.go`, `main.go`.

---

## High-Risk Framework Surfaces

### 1. Binding Overreach

- `ShouldBindJSON` directly into model structs
- PATCH endpoints binding maps and passing them straight to GORM
- missing validation tags on request structs

### 2. Middleware Coverage

- auth middleware applied to one route group but not another versioned group
- admin routes relying on path naming instead of a dedicated middleware / policy layer

### 3. GORM Escape Hatches

- `Raw`, `Exec`, `Order`, and string-built `Where` clauses
- `Updates(map[string]interface{})` with attacker-controlled maps

### 4. File and Command Helpers

- `c.File`, `os.ReadFile`, or path joins using `c.Query`
- `exec.Command("sh", "-c", ...)` hidden in utility services called by handlers

---

## Dangerous Patterns

```go
func UpdateUser(c *gin.Context) {
    var user models.User
    c.ShouldBindJSON(&user)
    db.Save(&user)
}

func Download(c *gin.Context) {
    c.File("/uploads/" + c.Query("file"))
}
```

---

## Detection Commands

```bash
grep -rn 'ShouldBindJSON|BindJSON|ShouldBind|Bind\\(' --include="*.go"
grep -rn 'gin\\.Default\\(|Use\\(|Group\\(' --include="*.go"
grep -rn 'Raw\\(|Exec\\(|Order\\(|Where\\(' --include="*.go"
grep -rn 'c\\.File\\(|os\\.ReadFile\\(|filepath\\.Join\\(|exec\\.Command' --include="*.go"
```

---

## Audit Questions

- Are request DTOs distinct from persistence models?
- Does every sensitive route group carry auth and role middleware consistently?
- Are GORM dynamic fragments constrained by allowlists?
- Are helper packages doing shell or filesystem work outside the handler layer?
