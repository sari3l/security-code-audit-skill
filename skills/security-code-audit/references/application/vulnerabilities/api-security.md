# API Security Vulnerabilities

This file focuses on runtime API weaknesses: authz drift, version downgrade, object/property exposure, and transport-specific control gaps.

Use `references/shared/artifacts/api-specs.md` when reviewing OpenAPI, Swagger, Postman, GraphQL schema, or collection artifacts as recon sources. That artifact module helps discover hidden routes, stale examples, and auth-declaration drift; this file covers the runtime weakness itself.

## Root-Cause Lens Across API Surfaces

Do not define API bugs only by one transport-specific POC.

Define them by the semantic failure:
- gateway, router, serializer, and business logic disagree on version, subject, object, field set, or operation shape
- one transport or version applies stronger parsing and policy than another
- the same logical action becomes more permissive when expressed through a different path, header, media type, batch shape, or schema

This means review should focus on:
- how versions are selected and normalized
- how object IDs, tenant keys, and field sets are parsed across REST, GraphQL, internal APIs, and background triggers
- whether deprecated or alternate paths are still attached to weaker middleware or serializers

## Version Drift, Downgrade, And Cross-Version Authorization

Treat each API version as a separate trust boundary.

Common failures:
- `/v1/` lacks authorization or field filtering that exists in `/v2/`
- old mobile or partner endpoints still accept weaker tokens, scopes, or signatures
- deprecated endpoints remain reachable through gateways, headers, or alternate version selectors
- newer validation exists only in one transport such as REST but not GraphQL or internal APIs
- users can force downgrade through path, header, query, or media-type version negotiation

### Audit Method

1. enumerate all version selectors: path, header, media type, subdomain, and internal route groups
2. diff middleware, guards, serializers, and ownership checks between versions
3. replay the same unauthorized or cross-tenant request against every supported version
4. compare response shape and hidden fields across versions, not just status codes
5. verify deprecated versions are truly disabled at router and gateway layers

### Detection Commands

```bash
grep -rn '/v1/\\|/v2/\\|/v3/\\|versioning\\|X-API-Version\\|Accept: application/vnd' .
grep -rn 'Deprecated\\|legacy\\|compat\\|backward' .
grep -rn 'router\\.use\\|RouteGroupBuilder\\|MapGroup\\|version' --include='*.py' --include='*.js' --include='*.ts' --include='*.java' --include='*.go' --include='*.cs'
```

---

## BOLA / IDOR (Broken Object Level Authorization)

The most common API vulnerability. User supplies an object ID and the server returns or modifies it without verifying ownership.

### Direct Object Reference Without Ownership Check

**Python (Django) - VULNERABLE:**
```python
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_invoice(request, invoice_id):
    invoice = Invoice.objects.get(id=invoice_id)  # No ownership check
    return Response(InvoiceSerializer(invoice).data)
```

**Python (Django) - FIXED:**
```python
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_invoice(request, invoice_id):
    invoice = get_object_or_404(
        Invoice, id=invoice_id, user=request.user  # Ownership filter
    )
    return Response(InvoiceSerializer(invoice).data)
```

**JavaScript (Express) - VULNERABLE:**
```javascript
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id); // No ownership check
  res.json(order);
});
```

**JavaScript (Express) - FIXED:**
```javascript
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id  // Ownership filter
  });
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});
```

**Java (Spring) - VULNERABLE:**
```java
@GetMapping("/api/documents/{id}")
public ResponseEntity<Document> getDocument(@PathVariable Long id) {
    return ResponseEntity.ok(documentRepository.findById(id).orElseThrow());
}
```

**Java (Spring) - FIXED:**
```java
@GetMapping("/api/documents/{id}")
public ResponseEntity<Document> getDocument(
        @PathVariable Long id,
        @AuthenticationPrincipal UserDetails user) {
    Document doc = documentRepository.findByIdAndOwnerId(id, user.getId())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    return ResponseEntity.ok(doc);
}
```

### Common IDOR Patterns

| Endpoint Pattern | Attack |
|---|---|
| `GET /api/users/{id}/profile` | Change `{id}` to another user's ID |
| `GET /api/files/{fileId}/download` | Enumerate file IDs |
| `PUT /api/orders/{orderId}` | Modify another user's order |
| `DELETE /api/comments/{commentId}` | Delete someone else's comment |
| `GET /api/receipts/{receiptId}.pdf` | Access another user's receipt |
| `GET /api/messages?conversationId=X` | Read someone else's messages |

### Detection Commands

```bash
# Find route handlers that take an ID parameter but don't filter by user
grep -rn 'findById\|objects\.get\|findOne.*_id\|findByPk' --include='*.py' --include='*.js' --include='*.ts' --include='*.java' | grep -v 'user\|owner\|author\|creator\|requester'

# Find endpoints with path parameters
grep -rn '/:id\|/{id}\|/<int:' --include='*.py' --include='*.js' --include='*.ts' --include='*.java' --include='*.go'

# Find endpoints that only check authentication, not authorization
grep -rn '@login_required\|@authenticated\|IsAuthenticated\|auth\b' --include='*.py' --include='*.js' -A5 | grep 'get\|find\|fetch' | grep -v 'user.*=\|owner\|filter.*user'
```

---

## Broken Authentication

### JWT Vulnerabilities

**alg:none bypass:**
```python
# VULNERABLE: library accepts alg=none
import jwt
payload = jwt.decode(token, options={"verify_signature": False})
# or library doesn't enforce algorithm
payload = jwt.decode(token, secret)  # Attacker sends alg: "none"
```

**FIXED: Always specify allowed algorithms:**
```python
payload = jwt.decode(
    token,
    secret_key,
    algorithms=["HS256"]  # Explicit allowlist
)
```

**JWT secret brute-force (weak secret):**
```bash
# If JWT uses HS256 with a weak secret, it can be cracked
# Detection: check for hardcoded/weak secrets
grep -rn 'jwt.*secret\|JWT_SECRET\|token.*secret' --include='*.py' --include='*.js' --include='*.env' --include='*.yaml'
```

**Token in URL:**
```bash
# VULNERABLE: token passed as query parameter (logged in server logs, browser history, referrer)
# GET /api/data?token=eyJhbGciOiJIUzI1NiJ9...
grep -rn 'token.*=.*req\.query\|token.*=.*request\.GET\|token.*=.*params\.get' --include='*.py' --include='*.js'
```

**Missing token expiry:**
```bash
# Check for JWT creation without exp claim
grep -rn 'jwt\.encode\|jwt\.sign\|createToken\|generateToken' --include='*.py' --include='*.js' --include='*.java' -A5 | grep -v 'exp\|expir\|ttl'
```

### Session Management Flaws

```bash
# Hardcoded session secrets
grep -rn 'session.*secret\|SECRET_KEY\s*=' --include='*.py' --include='*.js' --include='*.env'

# Missing session invalidation on password change/logout
grep -rn 'password.*change\|change.*password\|set_password\|updatePassword' --include='*.py' --include='*.js' -A10 | grep -v 'session.*flush\|session.*destroy\|invalidate\|logout\|revoke'
```

---

## Mass Assignment (Broken Object Property Level Authorization)

### Dynamic Field Mapping

**Go (GORM) - VULNERABLE:**
```go
func UpdateProfile(c *gin.Context) {
    var updates map[string]interface{}
    c.BindJSON(&updates) // Attacker: {"name":"x","role":"admin","is_verified":true}
    db.Model(&User{}).Where("id = ?", userID).Updates(updates)
}
```

**Go - FIXED:**
```go
func UpdateProfile(c *gin.Context) {
    var req struct {
        Name  string `json:"name"`
        Bio   string `json:"bio"`
        Phone string `json:"phone"`
    }
    c.BindJSON(&req)
    db.Model(&User{}).Where("id = ?", userID).Updates(User{
        Name:  req.Name,
        Bio:   req.Bio,
        Phone: req.Phone,
    })
}
```

### Detection Commands

```bash
# Python: fields = '__all__' in serializers
grep -rn "__all__" --include='*.py' | grep -i 'field\|serial'

# JavaScript: spreading req.body into database operations
grep -rn 'req\.body\|\.\.\.body\|Object\.assign.*body' --include='*.js' --include='*.ts' | grep -i 'create\|update\|save\|insert'

# Java: @RequestBody with entity classes (not DTOs)
grep -rn '@RequestBody' --include='*.java' | grep -v 'DTO\|Dto\|Request\|Form\|Command'

# Go: direct binding to model structs
grep -rn 'ShouldBindJSON\|BindJSON\|Decode' --include='*.go' -B2 | grep -i 'model\|entity\|User\|Account\|Order'
```

---

## Unrestricted Resource Consumption

### Missing Rate Limiting

```bash
# Check for rate limiting middleware
grep -rn 'rateLimit\|rate_limit\|throttle\|RateLimit\|@Throttle' --include='*.py' --include='*.js' --include='*.java' --include='*.go'

# Expensive operations without throttling
grep -rn 'sendEmail\|send_email\|send_sms\|generateReport\|export' --include='*.py' --include='*.js' | grep -v 'throttle\|rate\|limit\|cooldown'
```

### Missing Pagination Limits

**VULNERABLE:**
```python
@api_view(['GET'])
def list_users(request):
    limit = int(request.GET.get('limit', 100))
    # Attacker: ?limit=9999999
    users = User.objects.all()[:limit]
```

**FIXED:**
```python
@api_view(['GET'])
def list_users(request):
    limit = min(int(request.GET.get('limit', 20)), 100)  # Hard cap
    page = int(request.GET.get('page', 1))
    offset = (page - 1) * limit
    users = User.objects.all()[offset:offset + limit]
```

### Missing File Size Limits

```bash
# Find file upload handlers without size restrictions
grep -rn 'upload\|multipart\|file.*save\|putObject\|writeFile' --include='*.py' --include='*.js' --include='*.java' | grep -v 'max.*size\|limit\|MAX_CONTENT_LENGTH\|maxFileSize\|sizeLimit'

# Check for configured upload limits
grep -rn 'MAX_CONTENT_LENGTH\|maxFileSize\|upload_max\|client_max_body_size\|multipart.*max' --include='*.py' --include='*.js' --include='*.java' --include='*.conf' --include='*.yaml'
```

---

## Broken Function Level Authorization

Admin or privileged endpoints accessible to regular users.

### Common Patterns

**Python (Django) - VULNERABLE:**
```python
# No permission check beyond login
@login_required
def admin_delete_user(request, user_id):
    User.objects.get(id=user_id).delete()
    return JsonResponse({'status': 'deleted'})
```

**Python - FIXED:**
```python
from django.contrib.admin.views.decorators import staff_member_required

@staff_member_required
def admin_delete_user(request, user_id):
    User.objects.get(id=user_id).delete()
    return JsonResponse({'status': 'deleted'})

# Or with DRF permissions:
class AdminUserView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
```

### Detection Commands

```bash
# Find admin/management routes
grep -rn 'admin\|manage\|internal\|backoffice\|staff\|superuser\|debug' --include='*.py' --include='*.js' --include='*.java' --include='*.go' | grep -i 'route\|path\|url\|endpoint\|mapping\|router\|app\.\(get\|post\|put\|delete\)'

# Find admin routes missing permission decorators
grep -rn 'def admin_\|/admin/\|/manage/\|/internal/' --include='*.py' -B3 | grep -v 'staff_member\|IsAdmin\|is_superuser\|permission\|role.*admin'

# Find privileged operations without role checks
grep -rn 'delete_user\|ban_user\|update_role\|set_admin\|promote\|impersonate' --include='*.py' --include='*.js' --include='*.java' | grep -v 'admin\|permission\|role\|authorize'
```

---

## GraphQL-Specific Vulnerabilities

### Introspection Enabled in Production

```bash
# Check if introspection is enabled
grep -rn 'introspection' --include='*.py' --include='*.js' --include='*.ts' --include='*.java' --include='*.yaml' --include='*.json'

# Test:
# curl -X POST https://target/graphql -H 'Content-Type: application/json' \
#   -d '{"query":"{ __schema { types { name } } }"}'
```

### Batching Attacks

**VULNERABLE: No limit on batched queries:**
```javascript
// GraphQL server accepts arrays of queries
// Attacker sends 1000 login attempts in a single HTTP request,
// bypassing per-request rate limiting:
// POST /graphql
// [
//   {"query":"mutation{login(user:\"admin\",pass:\"pass1\"){token}}"},
//   {"query":"mutation{login(user:\"admin\",pass:\"pass2\"){token}}"},
//   ... (1000 more)
// ]
```

**FIXED:**
```javascript
const server = new ApolloServer({
  // ...
  allowBatchedHttpRequests: false,
  // or limit batch size:
  // plugins: [batchLimitPlugin({ maxBatchSize: 5 })]
});
```

### Nested Query DoS (Query Depth Attack)

**VULNERABLE:**
```graphql
# Deeply nested query consuming exponential resources
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends { name }
          }
        }
      }
    }
  }
}
```

**FIXED: Set query depth and complexity limits:**
```javascript
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  validationRules: [
    depthLimit(5),
    createComplexityLimitRule(1000),
  ],
});
```

### Detection Commands

```bash
# Find GraphQL schemas with deeply nested types
grep -rn 'type.*{' --include='*.graphql' --include='*.gql'

# Check for query depth/complexity limits
grep -rn 'depthLimit\|depth_limit\|complexityLimit\|complexity_limit\|maxDepth\|max_depth\|query_cost\|queryCost' --include='*.py' --include='*.js' --include='*.ts' --include='*.java'

# Check for batching configuration
grep -rn 'batch\|allowBatchedHttpRequests' --include='*.js' --include='*.ts' --include='*.py'
```

---

## REST-Specific Vulnerabilities

### PATCH/PUT Mass Assignment

**VULNERABLE:**
```javascript
app.patch('/api/users/:id', auth, async (req, res) => {
  // PATCH allows partial updates - attacker sends {"role": "admin"}
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(user);
});
```

**FIXED:**
```javascript
const allowedFields = ['name', 'email', 'phone', 'bio'];

app.patch('/api/users/:id', auth, async (req, res) => {
  if (req.params.id !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const updates = {};
  for (const field of allowedFields) {
    if (req.body[field] !== undefined) {
      updates[field] = req.body[field];
    }
  }
  const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true });
  res.json(user);
});
```

### HTTP Verb Tampering

```bash
# Check if endpoints restrict HTTP methods
# VULNERABLE: route accepts all methods
grep -rn 'app\.all\|@app\.route.*methods' --include='*.py' --include='*.js'

# Test: if GET /api/users is protected but the same handler serves DELETE,
# an attacker might DELETE /api/users to wipe data
```

### HTTP Parameter Pollution

```
# Attacker sends duplicate parameters to bypass validation:
# POST /transfer?amount=100&amount=-100
# Some frameworks take first value, some take last, some take array
# If validation checks first and business logic uses last => bypass

# Detection: check how the framework handles duplicate params
```

### Detection Commands

```bash
# Find routes that don't restrict HTTP methods
grep -rn 'app\.all\b' --include='*.js' --include='*.ts'
grep -rn "@app.route.*methods" --include='*.py' | grep -v "methods=\['"

# Find PUT/PATCH without field filtering
grep -rn 'PUT\|PATCH\|put\|patch' --include='*.py' --include='*.js' --include='*.java' --include='*.go' -A10 | grep -i 'body\|request' | grep -i 'update\|save\|set' | grep -v 'allowedFields\|permitted\|whitelist\|allowlist'

# Find endpoints accepting file IDs without auth checks
grep -rn 'download\|export\|file.*id\|attachment' --include='*.py' --include='*.js' --include='*.java' | grep -i 'route\|path\|url\|get\b'
```

---

## Combined Detection Checklist

For every API endpoint, verify:

| Check | Question |
|---|---|
| **Authentication** | Does it require a valid token/session? |
| **Object-level authz** | Does it verify the user owns/can access the requested object? |
| **Function-level authz** | Does it verify the user's role allows this operation? |
| **Property-level authz** | Does it restrict which fields can be read/written? |
| **Input validation** | Are types, ranges, and formats enforced? |
| **Rate limiting** | Is there a per-user/IP rate limit? |
| **Pagination** | Are list endpoints capped? |
| **Output filtering** | Does the response exclude sensitive fields? |
