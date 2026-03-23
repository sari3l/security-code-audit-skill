# Go Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers standard library, Gin, Echo, Chi, Fiber, and common Go web patterns.

---

## C1: Injection

### Key Questions
- Are SQL queries built with string concatenation or `fmt.Sprintf`?
- Does any code call `exec.Command` with user-controlled arguments via a shell?
- Is `template.HTML()` used to bypass template escaping?
- Is `text/template` used instead of `html/template` for web output?
- Are LDAP or other query strings built from user input?

### Commonly Missed
- `fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)` passed to `db.Query`
- `exec.Command("sh", "-c", userInput)` invoking a shell
- `template.HTML(userInput)` casting user data to unescaped HTML type
- `text/template` used for HTML output (no auto-escaping)
- `database/sql` `Query` with string formatting instead of `$1` placeholders
- GORM `Where` with raw string concatenation
- `go-pg` raw queries with string interpolation

### Dangerous Patterns

```go
// SQL injection via fmt.Sprintf
query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)
rows, err := db.Query(query)

// SQL injection via string concatenation
rows, err := db.Query("SELECT * FROM users WHERE name = '" + name + "'")

// GORM raw string injection
db.Where("name = '" + name + "'").Find(&users)
db.Raw("SELECT * FROM users WHERE id = " + id).Scan(&user)

// Command injection via shell
cmd := exec.Command("sh", "-c", "ping "+userInput)
cmd := exec.Command("bash", "-c", fmt.Sprintf("grep %s /var/log/app.log", pattern))

// Template injection
tmpl := template.Must(template.New("").Parse(userInput))  // user controls template

// Using text/template for HTML (no auto-escaping)
import "text/template"
tmpl, _ := template.New("page").Parse("<div>{{.UserInput}}</div>")
```

### Safe Alternatives

```go
// Parameterized SQL (database/sql)
rows, err := db.Query("SELECT * FROM users WHERE id = $1", userID)
// MySQL uses ? instead of $1
rows, err := db.Query("SELECT * FROM users WHERE id = ?", userID)

// GORM parameterized
db.Where("name = ?", name).Find(&users)
db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(&user)

// Safe subprocess (no shell)
cmd := exec.Command("ping", "-c", "1", userInput)
// Validate userInput before use

// html/template for web output (auto-escapes)
import "html/template"
tmpl, _ := template.New("page").Parse("<div>{{.UserInput}}</div>")

// Never parse user input as a template
// Instead, pass user data as template variables
```

### Grep Detection Patterns

```bash
# SQL injection
grep -rn 'fmt\.Sprintf.*SELECT\|fmt\.Sprintf.*INSERT\|fmt\.Sprintf.*UPDATE\|fmt\.Sprintf.*DELETE' --include="*.go"
grep -rn 'db\.Query(".*+\|db\.Exec(".*+' --include="*.go"
grep -rn 'db\.Raw(".*+\|\.Where(".*+' --include="*.go" | grep -v "?"

# Command injection
grep -rn 'exec\.Command("sh"\|exec\.Command("bash"\|exec\.Command("/bin/sh"' --include="*.go"
grep -rn 'exec\.Command(' --include="*.go"

# Template injection
grep -rn "template\.HTML(" --include="*.go"
grep -rn '"text/template"' --include="*.go"  # should be html/template for web
grep -rn "template\.Must.*Parse(" --include="*.go" | grep -v "string literal"

# GORM raw queries
grep -rn "\.Raw(" --include="*.go"
grep -rn "\.Where(" --include="*.go" | grep "+"
```

---

## C2: Authentication

### Key Questions
- Is JWT algorithm pinned when verifying tokens?
- Is the JWT signing key strong and from a secure source?
- Are sessions managed securely (secure cookies, expiry)?
- Is bcrypt/argon2 used for password hashing?
- Are rate limits applied to login endpoints?

### Commonly Missed
- `jwt-go` (dgrijalva/jwt-go) is unmaintained; should use `golang-jwt/jwt`
- Not checking `token.Method` algorithm before accepting
- JWT secret from hardcoded string or weak environment variable
- Session cookies missing `Secure`, `HttpOnly`, `SameSite` flags
- `bcrypt.DefaultCost` (10) may be too low for modern hardware
- No rate limiting on login, password reset, or OTP endpoints
- Password comparison using `==` instead of `subtle.ConstantTimeCompare`

### Dangerous Patterns

```go
// JWT: not checking algorithm
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return []byte(secret), nil  // accepts any algorithm
})

// JWT: weak secret
var jwtSecret = []byte("mysecret")

// JWT: using deprecated library
import "github.com/dgrijalva/jwt-go"  // unmaintained, use golang-jwt/jwt

// Weak password hashing
import "crypto/sha256"
hash := sha256.Sum256([]byte(password))  // no salt

// Insecure cookie
http.SetCookie(w, &http.Cookie{
    Name:  "session",
    Value: sessionID,
    // missing Secure, HttpOnly, SameSite
})

// Timing attack on comparison
if userToken == storedToken {
    // grant access
}
```

### Safe Alternatives

```go
// JWT: verify algorithm
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return []byte(secret), nil
})

// JWT: strong secret from environment
secret := os.Getenv("JWT_SECRET")
if len(secret) < 32 {
    log.Fatal("JWT_SECRET must be at least 32 characters")
}

// Use golang-jwt/jwt/v5
import "github.com/golang-jwt/jwt/v5"

// bcrypt for passwords
import "golang.org/x/crypto/bcrypt"
hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
err := bcrypt.CompareHashAndPassword(hash, []byte(password))

// Secure cookie
http.SetCookie(w, &http.Cookie{
    Name:     "session",
    Value:    sessionID,
    Secure:   true,
    HttpOnly: true,
    SameSite: http.SameSiteStrictMode,
    MaxAge:   3600,
    Path:     "/",
})

// Constant-time comparison
import "crypto/subtle"
if subtle.ConstantTimeCompare([]byte(userToken), []byte(storedToken)) == 1 {
    // grant access
}
```

### Grep Detection Patterns

```bash
# JWT issues
grep -rn "jwt\.Parse\|jwt\.ParseWithClaims" --include="*.go" -A 5 | grep -v "Method\.\|SigningMethod"
grep -rn "dgrijalva/jwt-go" --include="*.go" --include="go.mod"

# Weak secrets
grep -rn 'jwtSecret\|jwt.*Secret\|signingKey' --include="*.go" | grep '=.*"'

# Weak hashing
grep -rn "sha256\.Sum\|sha1\.Sum\|md5\.Sum" --include="*.go" | grep -i "password"

# Cookie security
grep -rn "SetCookie\|http\.Cookie{" --include="*.go" -A 10 | grep -v "Secure\|HttpOnly\|SameSite"

# Timing attacks
grep -rn "==.*token\|==.*password\|==.*secret" --include="*.go"
```

---

## C3: Authorization

### Key Questions
- Does every handler have authentication middleware?
- Are resource lookups filtered by the authenticated user?
- Is middleware applied at the router level (not per-handler)?
- Is IDOR prevented?

### Commonly Missed
- Missing auth middleware on specific routes (especially after refactoring)
- IDOR: `db.First(&doc, id)` without `WHERE user_id = ?`
- File access: `http.ServeFile(w, r, userInput)` allowing path traversal
- Middleware ordering: auth middleware applied after vulnerable handler
- Group-level middleware not covering all sub-routes
- Admin routes in the same router group as public routes

### Dangerous Patterns

```go
// Missing auth middleware
router.GET("/api/admin/users", listUsers)  // no auth middleware

// IDOR - no ownership check
func getDocument(c *gin.Context) {
    id := c.Param("id")
    var doc Document
    db.First(&doc, id)  // any user can access any document
    c.JSON(200, doc)
}

// Path traversal via file serving
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    http.ServeFile(w, r, "/uploads/"+filename)  // ../../etc/passwd
}
```

### Safe Alternatives

```go
// Auth middleware on route group
api := router.Group("/api")
api.Use(authMiddleware())
{
    api.GET("/documents/:id", getDocument)
    api.POST("/documents", createDocument)
}

admin := router.Group("/admin")
admin.Use(authMiddleware(), adminRequired())
{
    admin.GET("/users", listUsers)
}

// Ownership check
func getDocument(c *gin.Context) {
    id := c.Param("id")
    userID := c.MustGet("userID").(uint)
    var doc Document
    result := db.Where("id = ? AND user_id = ?", id, userID).First(&doc)
    if result.Error != nil {
        c.JSON(404, gin.H{"error": "not found"})
        return
    }
    c.JSON(200, doc)
}

// Path traversal prevention
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := filepath.Base(r.URL.Query().Get("file"))  // strip path components
    safePath := filepath.Join("/uploads", filename)
    if !strings.HasPrefix(safePath, "/uploads/") {
        http.Error(w, "Forbidden", 403)
        return
    }
    http.ServeFile(w, r, safePath)
}
```

### Grep Detection Patterns

```bash
# Routes without middleware
grep -rn "\.GET(\|\.POST(\|\.PUT(\|\.DELETE(\|\.PATCH(" --include="*.go" | grep -v "Use(\|middleware\|auth"

# IDOR
grep -rn "db\.First(\|db\.Find(\|db\.Where(" --include="*.go" | grep "Param\|Query" | grep -v "user_id\|userID\|owner"

# Path traversal
grep -rn "http\.ServeFile\|os\.Open\|os\.ReadFile\|ioutil\.ReadFile" --include="*.go" | grep "Param\|Query\|FormValue"

# File path from user input
grep -rn "filepath\.Join(.*Param\|filepath\.Join(.*Query\|filepath\.Join(.*FormValue" --include="*.go"
```

---

## C4: Mass Assignment

### Key Questions
- Are request bodies bound directly to database models?
- Are there separate structs for input binding vs. database models?
- Can users set privileged fields (role, isAdmin, verified) through binding?
- Is `json.Unmarshal` used directly on database models with untrusted input?

### Commonly Missed
- Gin `c.ShouldBindJSON(&model)` or `c.BindJSON(&model)` binding directly to a GORM/DB model
- Echo `c.Bind(&model)` without field filtering
- GORM `db.Create(&requestModel)` where `requestModel` came straight from user input
- GORM `db.Model(&user).Updates(requestBody)` passing unfiltered request body
- `json.Unmarshal(body, &dbModel)` deserializing directly into a database model
- `mapstructure.Decode(input, &model)` without field control
- Struct tags like `json:"role"` on database models that should not be user-settable
- Bulk update endpoints that accept arbitrary field maps

### Dangerous Patterns

```go
// Gin: binding directly to DB model
func createUser(c *gin.Context) {
    var user User  // DB model with IsAdmin, Role fields
    c.ShouldBindJSON(&user)  // attacker sets {"is_admin": true}
    db.Create(&user)
}

// Gin: binding and updating without filtering
func updateUser(c *gin.Context) {
    var user User
    c.BindJSON(&user)  // can set IsAdmin=true, Role="superadmin"
    db.Save(&user)
}

// GORM: passing request body directly to Updates
func updateProfile(c *gin.Context) {
    var body map[string]interface{}
    c.ShouldBindJSON(&body)
    db.Model(&user).Updates(body)  // attacker sends {"role": "admin"}
}

// Echo: binding directly to DB model
func createItem(c echo.Context) error {
    var item Item  // DB model
    c.Bind(&item)  // no field filtering
    db.Create(&item)
    return c.JSON(200, item)
}

// json.Unmarshal directly to database model
func handler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    var user User  // DB model
    json.Unmarshal(body, &user)  // attacker controls all fields
    db.Create(&user)
}

// mapstructure without field control
var dbModel User
mapstructure.Decode(inputMap, &dbModel)  // all fields populated from input
db.Save(&dbModel)
```

### Safe Alternatives

```go
// Separate request DTO from DB model
type CreateUserRequest struct {
    Name  string `json:"name" binding:"required"`
    Email string `json:"email" binding:"required,email"`
    // No IsAdmin, Role, or other privileged fields
}

type User struct {
    gorm.Model
    Name    string
    Email   string
    IsAdmin bool
    Role    string
}

func createUser(c *gin.Context) {
    var req CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    user := User{
        Name:  req.Name,
        Email: req.Email,
        // IsAdmin and Role not set from request
    }
    db.Create(&user)
}

// Whitelist fields for update
type UpdateUserRequest struct {
    Name  string `json:"name"`
    Email string `json:"email"`
}

func updateUser(c *gin.Context) {
    var req UpdateUserRequest
    c.ShouldBindJSON(&req)
    db.Model(&User{}).Where("id = ?", userID).Updates(map[string]interface{}{
        "name":  req.Name,
        "email": req.Email,
    })
}

// GORM Select to whitelist columns
db.Model(&user).Select("Name", "Email").Updates(req)

// Echo with separate DTO
func updateItem(c echo.Context) error {
    var req UpdateItemRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(400, map[string]string{"error": "invalid input"})
    }
    db.Model(&Item{}).Where("id = ?", id).Updates(map[string]interface{}{
        "title":       req.Title,
        "description": req.Description,
    })
    return c.JSON(200, map[string]string{"status": "updated"})
}
```

### Grep Detection Patterns

```bash
# Binding directly to DB model then saving
grep -rn "ShouldBindJSON\|BindJSON\|ShouldBind\|c\.Bind(" --include="*.go" -A 5 | grep "db\.Save\|db\.Create\|db\.Updates"

# Unfiltered Updates with map
grep -rn "\.Updates(" --include="*.go" | grep -v "map\[string\]interface\|Select("

# json.Unmarshal to model then DB operation
grep -rn "json\.Unmarshal\|json\.NewDecoder" --include="*.go" -A 5 | grep "db\.Save\|db\.Create\|db\.Updates"

# mapstructure.Decode without filtering
grep -rn "mapstructure\.Decode" --include="*.go" -A 3 | grep "db\.\|gorm\."

# Models with privileged fields and json tags
grep -rn 'IsAdmin\|Role\|Verified\|Permissions' --include="*.go" | grep 'json:"' | grep -v 'json:"-"'

# Echo Bind to DB model
grep -rn "c\.Bind(" --include="*.go" -A 5 | grep "db\.Create\|db\.Save"
```

---

## C5: Data Exposure

### Key Questions
- Are secrets hardcoded in source code?
- Are credentials stored outside the binary?
- Are sensitive struct fields excluded from JSON marshaling?
- Is TLS enforced?

### Commonly Missed
- Secrets in Go source files or config files committed to git
- Struct fields with `json:` tags exposing password hashes
- `fmt.Printf("%+v", user)` printing all struct fields including secrets
- Error messages leaking internal paths or credentials
- `.env` files or config YAML with plaintext secrets in repository

### Dangerous Patterns

```go
// Hardcoded credentials
const dbPassword = "supersecret"
var apiKey = "sk-live-abc123"

// Struct exposing sensitive fields
type User struct {
    ID           int    `json:"id"`
    Email        string `json:"email"`
    PasswordHash string `json:"password_hash"`  // exposed in JSON
    APIToken     string `json:"api_token"`       // exposed in JSON
}

// Logging full struct
log.Printf("User created: %+v", user)  // includes PasswordHash

// Error messages leaking info
if err != nil {
    http.Error(w, fmt.Sprintf("DB error: %v", err), 500)  // leaks DB details
}

// TLS disabled
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    },
}
```

### Safe Alternatives

```go
// Secrets from environment
dbPassword := os.Getenv("DB_PASSWORD")

// Exclude sensitive fields from JSON
type User struct {
    ID           int    `json:"id"`
    Email        string `json:"email"`
    PasswordHash string `json:"-"`  // excluded from JSON
    APIToken     string `json:"-"`  // excluded from JSON
}

// Separate response type
type UserResponse struct {
    ID    int    `json:"id"`
    Email string `json:"email"`
}

// Safe error messages
if err != nil {
    log.Printf("DB error: %v", err)  // log internally
    http.Error(w, "Internal server error", 500)  // generic to client
}

// TLS verification enabled (default)
client := &http.Client{}  // default transport verifies TLS
```

### Grep Detection Patterns

```bash
# Hardcoded secrets
grep -rn 'password\s*=\s*"' --include="*.go" -i
grep -rn 'apiKey\s*=\s*"' --include="*.go" -i
grep -rn 'secret\s*=\s*"' --include="*.go" -i
grep -rn 'token\s*=\s*"' --include="*.go" -i

# Exposed struct fields
grep -rn 'json:".*password\|json:".*secret\|json:".*token' --include="*.go" | grep -v 'json:"-"'

# Verbose error to client
grep -rn "http\.Error(.*err\|http\.Error.*fmt\.Sprintf" --include="*.go"

# TLS skip verify
grep -rn "InsecureSkipVerify:\s*true" --include="*.go"

# Logging structs
grep -rn 'Printf.*%+v\|Printf.*%v' --include="*.go" | grep -i "user\|cred\|auth\|session"
```

---

## C6: Misconfiguration

### Key Questions
- Are debug endpoints disabled in production?
- Are verbose errors hidden from clients?
- Is TLS configured with strong cipher suites?
- Are security headers set?
- Is pprof disabled in production?

### Commonly Missed
- `net/http/pprof` imported and accessible in production (exposes profiling data)
- `gin.SetMode(gin.DebugMode)` in production
- Default `http.ListenAndServe` without TLS
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Go default TLS config accepting TLS 1.0/1.1
- Verbose error responses: `c.JSON(500, gin.H{"error": err.Error()})`
- CORS middleware with `AllowAllOrigins: true`

### Dangerous Patterns

```go
// pprof exposed in production
import _ "net/http/pprof"
// Accessible at /debug/pprof/

// Debug mode
gin.SetMode(gin.DebugMode)

// Verbose errors to client
func handler(c *gin.Context) {
    result, err := db.Query(...)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})  // leaks DB errors
    }
}

// No TLS
http.ListenAndServe(":8080", router)

// Weak TLS config
server := &http.Server{
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS10,  // allows TLS 1.0
    },
}

// CORS wide open
router.Use(cors.New(cors.Config{
    AllowAllOrigins: true,
}))

// Missing security headers (not using any header middleware)
```

### Safe Alternatives

```go
// Remove pprof import in production or protect it
// Only import pprof in development builds

// Production mode
gin.SetMode(gin.ReleaseMode)

// Generic errors to client
func handler(c *gin.Context) {
    result, err := db.Query(...)
    if err != nil {
        log.Printf("DB error: %v", err)
        c.JSON(500, gin.H{"error": "internal server error"})
    }
}

// TLS with strong config
server := &http.Server{
    Addr:    ":443",
    Handler: router,
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    },
}
server.ListenAndServeTLS("cert.pem", "key.pem")

// Security headers middleware
func securityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Header("Content-Security-Policy", "default-src 'self'")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Next()
    }
}

// Restrictive CORS
router.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"https://myapp.example.com"},
    AllowMethods:     []string{"GET", "POST"},
    AllowCredentials: true,
}))
```

### Grep Detection Patterns

```bash
# pprof in production
grep -rn 'net/http/pprof' --include="*.go"
grep -rn "/debug/pprof" --include="*.go"

# Debug mode
grep -rn "DebugMode\|SetMode.*Debug" --include="*.go"

# Verbose errors
grep -rn 'err\.Error()' --include="*.go" | grep -i "json\|write\|respond\|send"

# No TLS / weak TLS
grep -rn "ListenAndServe(" --include="*.go" | grep -v "TLS"
grep -rn "VersionTLS10\|VersionTLS11\|MinVersion.*tls\.VersionSSL" --include="*.go"

# CORS
grep -rn "AllowAllOrigins:\s*true\|AllowOrigins.*\\*" --include="*.go"

# Missing security headers
grep -rn "X-Frame-Options\|Content-Security-Policy\|Strict-Transport-Security" --include="*.go"
```

---

## C7: XSS (Cross-Site Scripting)

### Key Questions
- Is `template.HTML()` used to cast user data to unescaped HTML?
- Is `text/template` used instead of `html/template` for web responses?
- Are CSP headers configured?
- Is user input reflected in JSON responses served as `text/html`?

### Commonly Missed
- `template.HTML(userInput)` explicitly bypasses escaping
- `template.JS(userInput)` and `template.CSS(userInput)` bypass escaping in those contexts
- Using `text/template` for HTML output (common mistake)
- `fmt.Fprintf(w, "<h1>%s</h1>", userInput)` writing HTML directly
- JSON responses with `text/html` content type
- `template.Must(template.New("").Parse(userInput))` user-controlled templates

### Dangerous Patterns

```go
// template.HTML bypasses escaping
data := map[string]interface{}{
    "Content": template.HTML(userInput),  // XSS
}

// text/template has no auto-escaping
import "text/template"
tmpl, _ := template.New("page").Parse("<div>{{.UserInput}}</div>")

// Direct HTML writing
fmt.Fprintf(w, "<h1>Welcome, %s</h1>", username)

// Reflecting input in response header
w.Header().Set("Location", userInput)  // header injection

// JSON served as HTML
w.Header().Set("Content-Type", "text/html")
json.NewEncoder(w).Encode(map[string]string{"name": userInput})
```

### Safe Alternatives

```go
// html/template auto-escapes
import "html/template"
tmpl, _ := template.New("page").Parse("<div>{{.UserInput}}</div>")
// UserInput is auto-escaped

// Never cast user input to template.HTML
// If HTML rendering is needed, sanitize first with bluemonday
import "github.com/microcosm-cc/bluemonday"
p := bluemonday.UGCPolicy()
safeHTML := p.Sanitize(userInput)
data := map[string]interface{}{
    "Content": template.HTML(safeHTML),
}

// JSON with proper content type
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(response)

// CSP headers
w.Header().Set("Content-Security-Policy", "default-src 'self'")
```

### Grep Detection Patterns

```bash
# template.HTML with user data
grep -rn "template\.HTML(" --include="*.go"
grep -rn "template\.JS(\|template\.CSS(" --include="*.go"

# text/template for web output
grep -rn '"text/template"' --include="*.go"

# Direct HTML writing
grep -rn "Fprintf(.*<\|Fprintf.*html" --include="*.go"
grep -rn "WriteString(.*<\|Write(.*<" --include="*.go"

# CSP headers
grep -rn "Content-Security-Policy" --include="*.go"

# Content type issues
grep -rn 'Content-Type.*text/html' --include="*.go" | grep -v "template"
```

---

## C8: Dependencies

### Key Questions
- Has `govulncheck` been run?
- Are dependencies in `go.sum` current?
- Are there known CVEs in imported packages?
- Is the Go version itself current?

### Commonly Missed
- `govulncheck` not part of CI pipeline
- Indirect dependencies with vulnerabilities
- Go standard library CVEs (update Go version)
- Using deprecated or unmaintained packages
- `replace` directives in `go.mod` pointing to vulnerable forks

### High-Risk Packages to Check

| Package | Risk | Check for |
|---------|------|-----------|
| dgrijalva/jwt-go | Unmaintained, use golang-jwt/jwt | Algorithm confusion |
| gorilla/mux | Archived (but stable) | Consider chi or stdlib |
| golang.org/x/crypto | Periodic CVEs | Version currency |
| golang.org/x/net | HTTP/2 CVEs | Version currency |
| go-yaml/yaml | < v3 issues | Deserialization risks |
| gorm.io/gorm | SQL injection in older versions | Version currency |
| gin-gonic/gin | Periodic CVEs | Version currency |

### Grep Detection Patterns

```bash
# Run vulnerability check
# govulncheck ./...

# Check go.mod for known problematic packages
grep -rn "dgrijalva/jwt-go" go.mod go.sum
grep -rn "gorilla/" go.mod

# Check Go version
go version
grep "^go " go.mod

# Check for replace directives
grep -rn "replace" go.mod

# Check for outdated dependencies
# go list -m -u all
```

---

## C9: Cryptography

### Key Questions
- Is `crypto/rand` used for token generation (not `math/rand`)?
- Is bcrypt or argon2 used for password hashing?
- Is TLS 1.2+ enforced?
- Are keys stored securely?

### Commonly Missed
- `math/rand` seeded with `time.Now().UnixNano()` for tokens (predictable)
- `crypto/md5` or `crypto/sha1` for password hashing
- `crypto/sha256` without salt for passwords
- Hardcoded encryption keys
- Default TLS config allowing TLS 1.0/1.1
- `InsecureSkipVerify: true` disabling certificate verification

### Dangerous Patterns

```go
// Weak random
import "math/rand"
token := fmt.Sprintf("%d", rand.Int())

// Weak password hashing
import "crypto/md5"
hash := md5.Sum([]byte(password))

import "crypto/sha256"
hash := sha256.Sum256([]byte(password))  // no salt

// Hardcoded key
key := []byte("my-secret-key-16-bytes!")
block, _ := aes.NewCipher(key)

// Disabled TLS verification
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    },
}

// Weak TLS
server := &http.Server{
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS10,
    },
}
```

### Safe Alternatives

```go
// Cryptographically secure random
import "crypto/rand"
tokenBytes := make([]byte, 32)
_, err := rand.Read(tokenBytes)
token := base64.URLEncoding.EncodeToString(tokenBytes)

// bcrypt for passwords
import "golang.org/x/crypto/bcrypt"
hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
err := bcrypt.CompareHashAndPassword(hash, []byte(password))

// Or argon2
import "golang.org/x/crypto/argon2"
salt := make([]byte, 16)
rand.Read(salt)
hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

// AES-GCM with random nonce
block, _ := aes.NewCipher(key)  // key from secure storage
gcm, _ := cipher.NewGCM(block)
nonce := make([]byte, gcm.NonceSize())
rand.Read(nonce)
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

// Strong TLS
server := &http.Server{
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
}
```

### Grep Detection Patterns

```bash
# Weak random
grep -rn '"math/rand"' --include="*.go"
grep -rn "rand\.Int\|rand\.Intn\|rand\.Read" --include="*.go" | grep "math/rand\|math_rand"

# Weak hashing
grep -rn '"crypto/md5"\|"crypto/sha1"' --include="*.go"
grep -rn "md5\.Sum\|md5\.New\|sha1\.Sum\|sha1\.New" --include="*.go"
grep -rn "sha256\.Sum" --include="*.go" | grep -i "password"

# Hardcoded keys
grep -rn 'key\s*:=\s*\[\]byte("' --include="*.go"
grep -rn 'aes\.NewCipher(\[\]byte("' --include="*.go"

# Disabled TLS
grep -rn "InsecureSkipVerify:\s*true" --include="*.go"

# Weak TLS version
grep -rn "VersionTLS10\|VersionTLS11" --include="*.go"
```

---

## C10: SSRF (Server-Side Request Forgery)

### Key Questions
- Does any handler make HTTP requests using user-supplied URLs?
- Are webhook or callback URLs validated before fetching?
- Can internal/private IP ranges be reached through user-controlled URLs?
- Are HTTP redirects followed without validating the destination?
- Is DNS rebinding a concern with the default resolver?

### Commonly Missed
- `http.Get(userURL)` or `http.Post(userURL, ...)` with unvalidated user input
- `http.NewRequest("GET", userURL, nil)` passed to a client that follows redirects
- Default `http.Client` follows redirects automatically, potentially to internal hosts
- Cloud metadata endpoint `http://169.254.169.254/latest/meta-data/` reachable from application
- Webhook/callback URL handlers that fetch arbitrary URLs
- DNS rebinding: first lookup resolves to public IP (passes validation), second resolves to internal IP
- `net.Dial` / `net.DialTimeout` with user-controlled host and port
- URL parsing differences between validation and actual request (TOCTOU)
- IPv6 addresses like `[::1]` or `[0:0:0:0:0:ffff:127.0.0.1]` bypassing IPv4 blocklists
- Scheme confusion: `file://`, `gopher://`, `dict://` accepted by some HTTP libraries

### Dangerous Patterns

```go
// Direct HTTP request with user-controlled URL
func fetchURL(c *gin.Context) {
    url := c.Query("url")
    resp, err := http.Get(url)  // SSRF: user can request internal services
    // ...
}

// User-controlled URL in NewRequest
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    targetURL := r.FormValue("target")
    req, _ := http.NewRequest("GET", targetURL, nil)
    client := &http.Client{}
    resp, _ := client.Do(req)  // follows redirects to internal hosts
    // ...
}

// Webhook handler fetching arbitrary callback URL
func registerWebhook(c *gin.Context) {
    var webhook Webhook
    c.ShouldBindJSON(&webhook)
    // Later, application fetches webhook.CallbackURL without validation
    resp, _ := http.Post(webhook.CallbackURL, "application/json", body)
}

// Cloud metadata accessible
func handler(c *gin.Context) {
    url := c.Query("url")
    // Attacker sends: url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    resp, _ := http.Get(url)
}

// net.Dial with user-controlled address
func connectToHost(c *gin.Context) {
    host := c.Query("host")
    port := c.Query("port")
    conn, err := net.DialTimeout("tcp", host+":"+port, 5*time.Second)  // SSRF
    // ...
}

// Redirect following to internal hosts
client := &http.Client{}  // default follows up to 10 redirects
resp, _ := client.Get(userURL)  // initial URL is external, redirects to http://127.0.0.1/admin
```

### Safe Alternatives

```go
// Validate URL scheme and host before requesting
func isAllowedURL(rawURL string) bool {
    u, err := url.Parse(rawURL)
    if err != nil {
        return false
    }
    // Only allow http/https
    if u.Scheme != "http" && u.Scheme != "https" {
        return false
    }
    // Resolve and check IP
    host := u.Hostname()
    ips, err := net.LookupIP(host)
    if err != nil {
        return false
    }
    for _, ip := range ips {
        if isPrivateIP(ip) {
            return false
        }
    }
    return true
}

func isPrivateIP(ip net.IP) bool {
    privateRanges := []string{
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
    }
    for _, cidr := range privateRanges {
        _, network, _ := net.ParseCIDR(cidr)
        if network.Contains(ip) {
            return true
        }
    }
    return false
}

// Custom transport that validates connections
func safeClient() *http.Client {
    transport := &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            host, port, _ := net.SplitHostPort(addr)
            ips, err := net.LookupIP(host)
            if err != nil {
                return nil, err
            }
            for _, ip := range ips {
                if isPrivateIP(ip) {
                    return nil, fmt.Errorf("access to private IP %s denied", ip)
                }
            }
            dialer := &net.Dialer{Timeout: 10 * time.Second}
            return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
        },
    }
    return &http.Client{
        Transport: transport,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 3 {
                return fmt.Errorf("too many redirects")
            }
            // Re-validate redirect destination
            host := req.URL.Hostname()
            ips, _ := net.LookupIP(host)
            for _, ip := range ips {
                if isPrivateIP(ip) {
                    return fmt.Errorf("redirect to private IP denied")
                }
            }
            return nil
        },
    }
}

// Allowlist approach for webhooks
var allowedWebhookDomains = map[string]bool{
    "hooks.slack.com": true,
    "api.github.com":  true,
}

func validateWebhookURL(rawURL string) error {
    u, err := url.Parse(rawURL)
    if err != nil {
        return err
    }
    if !allowedWebhookDomains[u.Hostname()] {
        return fmt.Errorf("webhook domain not allowed: %s", u.Hostname())
    }
    return nil
}
```

### Grep Detection Patterns

```bash
# HTTP requests with user-controlled URLs
grep -rn "http\.Get(\|http\.Post(\|http\.Head(" --include="*.go" | grep -i "param\|query\|form\|input\|url\|user\|request"
grep -rn "http\.NewRequest(" --include="*.go" | grep -i "param\|query\|form\|input\|url\|user"

# Client.Do / Client.Get with variables
grep -rn "client\.Do\|client\.Get\|client\.Post" --include="*.go"

# net.Dial with user input
grep -rn "net\.Dial\|net\.DialTimeout\|net\.DialContext" --include="*.go"

# Cloud metadata URL
grep -rn "169\.254\.169\.254\|metadata\.google\|metadata\.azure" --include="*.go"

# Webhook/callback URL handling
grep -rn "webhook\|callback.*url\|callbackURL\|CallbackURL" --include="*.go" -i

# CheckRedirect customization (or lack thereof)
grep -rn "CheckRedirect" --include="*.go"

# URL from user input
grep -rn "r\.FormValue\|c\.Query\|c\.Param\|r\.URL\.Query" --include="*.go" | grep -i "url\|target\|dest\|endpoint\|host\|addr"
```

---

## C11: Logging & Monitoring

### Key Questions
- Are passwords, tokens, or API keys logged?
- Is PII logged without masking?
- Are authentication events logged?
- Is log injection possible?

### Commonly Missed
- `log.Printf("Request: %+v", req)` printing all fields including auth headers
- `fmt.Printf` or `log.Printf` with `%+v` on structs containing secrets
- `log.Printf("User: %s, Password: %s", username, password)` explicit credential logging
- Log injection via newlines in user input
- Sentry/error tracking capturing request bodies

### Dangerous Patterns

```go
// Logging passwords
log.Printf("Login: user=%s password=%s", username, password)

// Logging full request
log.Printf("Request: %+v", r)  // includes headers with Authorization

// Logging struct with secrets
log.Printf("Config: %+v", config)  // includes DB passwords, API keys

// PII in logs
log.Printf("New user: email=%s, ssn=%s", user.Email, user.SSN)

// Log injection
log.Printf("Login failed for user: %s", username)
// username = "admin\n2024-01-01 [INFO] Payment $10000 processed"
```

### Safe Alternatives

```go
// Log only non-sensitive data
log.Printf("Login attempt: user=%s", username)

// Use structured logging (zerolog, zap)
import "github.com/rs/zerolog/log"
log.Info().
    Str("event", "login").
    Str("user_id", user.ID).
    Msg("login attempt")
// Explicit field selection; no accidental leaks

// Sanitize log input
safeUsername := strings.ReplaceAll(username, "\n", "")
safeUsername = strings.ReplaceAll(safeUsername, "\r", "")

// Custom String()/MarshalJSON() on sensitive types
type Config struct {
    DBPassword string
    APIKey     string
}

func (c Config) String() string {
    return fmt.Sprintf("Config{DBPassword:[REDACTED], APIKey:[REDACTED]}")
}
```

### Grep Detection Patterns

```bash
# Logging sensitive data
grep -rn "log\..*password\|log\..*token\|log\..*secret\|log\..*apiKey\|log\..*api_key" --include="*.go" -i
grep -rn 'log\..*Authorization' --include="*.go"

# Logging full structs
grep -rn 'log\.Printf.*%+v\|log\.Printf.*%v' --include="*.go" | grep -i "config\|user\|cred\|auth\|request\|session"
grep -rn 'fmt\.Printf.*%+v\|fmt\.Println' --include="*.go" | grep -i "config\|user\|cred\|auth"

# PII in logs
grep -rn "log\..*Email\|log\..*email\|log\..*SSN\|log\..*Phone" --include="*.go"

# Debug print statements
grep -rn "fmt\.Print\|fmt\.Println\|fmt\.Printf" --include="*.go" | grep -v "_test\.go\|test_"
```

---

## C12: Infrastructure (IaC)

### Key Questions
- Does the container run as non-root?
- Is the Go binary statically linked (scratch or distroless base)?
- Are secrets outside Dockerfiles?
- Are multi-stage builds used?
- Are resource limits set?

### Commonly Missed
- Not using multi-stage build (shipping Go toolchain in production image)
- Not using `CGO_ENABLED=0` for static binary (may need libc in scratch)
- Secrets in Dockerfile or docker-compose.yml
- Missing `USER` directive
- `latest` tag instead of pinned version
- Missing health check endpoint
- Docker socket mounted into container

### Dangerous Patterns

```dockerfile
# Full Go image in production, running as root
FROM golang:1.22
WORKDIR /app
COPY . .
RUN go build -o /app/server
ENV DB_PASSWORD=secret
EXPOSE 8080
CMD ["/app/server"]
```

```yaml
# docker-compose.yml with secrets
services:
  app:
    environment:
      - DB_PASSWORD=mysecret
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    privileged: true
```

### Safe Alternatives

```dockerfile
# Multi-stage build, scratch base, non-root
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/server

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/server /server
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/server", "-healthcheck"]
ENTRYPOINT ["/server"]
```

```yaml
# docker-compose.yml with external secrets
services:
  app:
    env_file: .env  # in .gitignore
    read_only: true
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: "0.5"
```

```yaml
# Kubernetes secure pod
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
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
          memory: "256Mi"
          cpu: "500m"
```

### Grep Detection Patterns

```bash
# Dockerfile issues
grep -rn "FROM.*latest\|FROM golang:" Dockerfile* | grep -v "AS builder\|AS build"
grep -n "USER" Dockerfile*  # check if exists
grep -rn "^ENV.*PASSWORD\|^ENV.*SECRET\|^ENV.*KEY" Dockerfile*
grep -rn "CGO_ENABLED" Dockerfile*  # should be set to 0 for scratch

# Docker-compose secrets
grep -rn "PASSWORD\|SECRET\|KEY\|TOKEN" docker-compose*.yml | grep -v "#"
grep -rn "docker\.sock" docker-compose*.yml
grep -rn "privileged" docker-compose*.yml

# Kubernetes
grep -rn "privileged:\s*true" --include="*.yaml" --include="*.yml"
grep -rn "runAsUser:\s*0\|runAsNonRoot:\s*false" --include="*.yaml" --include="*.yml"
grep -rn "hostNetwork:\s*true" --include="*.yaml" --include="*.yml"

# Resource limits
grep -rn "resources:" --include="*.yaml" --include="*.yml" -A 5 | grep "limits"
```
