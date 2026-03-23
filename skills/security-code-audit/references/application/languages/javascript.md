# JavaScript / TypeScript Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers Node.js backends, React/Vue/Angular frontends, and full-stack frameworks (Next.js, Nuxt, Express).

---

## C1: Injection

### Key Questions
- Are any SQL queries built with template literals or string concatenation?
- Does any code call `eval()`, `Function()`, or `child_process.exec` with user input?
- Is NoSQL injection possible via MongoDB query objects?
- Is prototype pollution possible via deep merge or `Object.assign`?
- Are GraphQL queries vulnerable to injection or excessive depth?

### Commonly Missed
- Template literal SQL: `` db.query(`SELECT * FROM users WHERE id = ${id}`) ``
- `child_process.exec` (spawns a shell) vs `execFile` (does not)
- MongoDB `$where`, `$gt`, `$ne` operators from user input: `{ password: { $ne: "" } }`
- Prototype pollution via `_.merge`, `_.defaultsDeep`, `Object.assign` with `__proto__`
- Server-side template injection in EJS, Pug, Handlebars
- `RegExp` constructed from user input (ReDoS)

### Dangerous Patterns

```javascript
// SQL injection via template literal
const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
const result = await db.query("SELECT * FROM users WHERE name = '" + name + "'");

// SQL injection in Sequelize
db.query("SELECT * FROM users WHERE name = '" + name + "'", { type: QueryTypes.SELECT });

// Knex raw injection
knex.raw(`SELECT * FROM users WHERE id = ${id}`);

// Command injection
const { exec } = require("child_process");
exec("ping " + userInput);
exec(`convert ${filename} output.png`);

// Code injection
eval(userInput);
new Function("return " + userInput)();
setTimeout(userInput, 1000);  // string argument is eval'd
setInterval(userInput, 1000);

// NoSQL injection (MongoDB)
// If req.body.password = { "$ne": "" }, this returns all users
db.collection("users").findOne({ username: req.body.username, password: req.body.password });

// Prototype pollution
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];  // __proto__ can be set
  }
}

// RegExp DoS
const regex = new RegExp(userInput);  // attacker controls pattern
```

### Safe Alternatives

```javascript
// Parameterized SQL
const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);

// Sequelize parameterized
db.query("SELECT * FROM users WHERE name = :name", {
  replacements: { name },
  type: QueryTypes.SELECT,
});

// Knex parameterized
knex.raw("SELECT * FROM users WHERE id = ?", [id]);

// Safe subprocess
const { execFile } = require("child_process");
execFile("ping", ["-c", "1", userInput]);  // no shell

// MongoDB: validate input types
const username = String(req.body.username);
const password = String(req.body.password);
db.collection("users").findOne({ username, password: hashedPassword });

// Prototype pollution prevention
function safeMerge(target, source) {
  for (let key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    target[key] = source[key];
  }
}
// Or use Object.create(null) for lookup objects

// Safe RegExp
const escaped = userInput.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const regex = new RegExp(escaped);
```

### Grep Detection Patterns

```bash
# SQL injection
grep -rn 'query(`' --include="*.js" --include="*.ts"
grep -rn "query(\".*+" --include="*.js" --include="*.ts"
grep -rn "knex\.raw(" --include="*.js" --include="*.ts"

# Command injection
grep -rn "child_process" --include="*.js" --include="*.ts"
grep -rn "\.exec(" --include="*.js" --include="*.ts" | grep -i "child_process\|require"

# Code injection
grep -rn "eval(" --include="*.js" --include="*.ts"
grep -rn "new Function(" --include="*.js" --include="*.ts"
grep -rn "setTimeout(.*['\"]" --include="*.js" --include="*.ts"  # string arg

# NoSQL injection
grep -rn "findOne(\|find(\|findOneAndUpdate(" --include="*.js" --include="*.ts" | grep "req\.body\|req\.query\|req\.params"

# Prototype pollution
grep -rn "Object\.assign(\|\.merge(\|\.extend(\|\.defaultsDeep(" --include="*.js" --include="*.ts"

# RegExp from user input
grep -rn "new RegExp(" --include="*.js" --include="*.ts"
```

---

## C2: Authentication

### Key Questions
- Is JWT algorithm pinned and verified?
- Is JWT secret strong and stored securely?
- Are sessions configured with secure flags?
- Is OAuth state parameter validated?
- Are refresh tokens rotated on use?

### Commonly Missed
- `jsonwebtoken` not verifying algorithm: `jwt.verify(token, secret)` without `algorithms` option
- JWT secret from environment but defaulting to a weak fallback
- Express session with default `MemoryStore` in production
- `express-session` missing `secure`, `httpOnly`, `sameSite` flags
- OAuth `state` parameter not validated (CSRF on OAuth flow)
- Password comparison using `==` instead of constant-time comparison
- Missing rate limiting on authentication endpoints

### Dangerous Patterns

```javascript
// JWT: not pinning algorithm
const decoded = jwt.verify(token, secret);  // accepts any algorithm

// JWT: weak secret
const secret = "mysecret";
const secret = process.env.JWT_SECRET || "fallback-secret";  // weak fallback

// JWT: ignoring expiration
jwt.verify(token, secret, { ignoreExpiration: true });

// Insecure session config
app.use(session({
  secret: "keyboard cat",
  cookie: {}  // missing secure, httpOnly, sameSite
}));

// Timing attack on password comparison
if (userToken === storedToken) { /* grant access */ }

// OAuth: missing state validation
app.get("/callback", (req, res) => {
  // no check of req.query.state
  const code = req.query.code;
  exchangeCodeForToken(code);
});
```

### Safe Alternatives

```javascript
// JWT: pin algorithm
const decoded = jwt.verify(token, secret, { algorithms: ["HS256"] });

// JWT: strong secret from environment only
const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) throw new Error("JWT_SECRET too weak");

// Secure session config
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "strict",
    maxAge: 3600000,
  },
  store: new RedisStore({ client: redisClient }),
}));

// Constant-time comparison
const crypto = require("crypto");
const isValid = crypto.timingSafeEqual(
  Buffer.from(userToken),
  Buffer.from(storedToken)
);

// OAuth: validate state
app.get("/callback", (req, res) => {
  if (req.query.state !== req.session.oauthState) {
    return res.status(403).send("Invalid state");
  }
  exchangeCodeForToken(req.query.code);
});
```

### Grep Detection Patterns

```bash
# JWT issues
grep -rn "jwt\.verify(" --include="*.js" --include="*.ts" | grep -v "algorithms"
grep -rn "ignoreExpiration" --include="*.js" --include="*.ts"
grep -rn "JWT_SECRET\|jwt.*secret" --include="*.js" --include="*.ts" | grep -i "fallback\|default\|changeme"

# Session config
grep -rn "session(" --include="*.js" --include="*.ts" -A 10 | grep "secret:"

# Timing attacks
grep -rn "===.*token\|===.*password\|===.*secret" --include="*.js" --include="*.ts"

# OAuth
grep -rn "/callback" --include="*.js" --include="*.ts" -A 10 | grep -v "state"
```

---

## C3: Authorization

### Key Questions
- Does every route have authentication middleware?
- Are resource lookups filtered by the authenticated user?
- Is role-based access control consistently applied?
- Are GraphQL resolvers protected with auth checks?

### Commonly Missed
- Express routes missing `authenticate` middleware
- IDOR: `Model.findById(req.params.id)` without ownership check
- GraphQL resolvers without auth checks
- Next.js API routes without auth middleware (each file is independent)
- Nested resource access not checking parent ownership

### Dangerous Patterns

```javascript
// Missing auth middleware
app.get("/api/admin/users", (req, res) => {
  const users = await User.find();  // no auth check
  res.json(users);
});

// IDOR - no ownership check
app.get("/api/documents/:id", authenticate, async (req, res) => {
  const doc = await Document.findById(req.params.id);  // any user can read any doc
  res.json(doc);
});

// Next.js API route without auth
// pages/api/admin/users.ts
export default async function handler(req, res) {
  const users = await prisma.user.findMany();  // no auth
  res.json(users);
}

// GraphQL resolver without auth
const resolvers = {
  Query: {
    users: () => User.findAll(),  // anyone can query all users
  },
};
```

### Safe Alternatives

```javascript
// Auth middleware on every protected route
app.get("/api/admin/users", authenticate, requireRole("admin"), async (req, res) => {
  const users = await User.find();
  res.json(users);
});

// Ownership check
app.get("/api/documents/:id", authenticate, async (req, res) => {
  const doc = await Document.findOne({ _id: req.params.id, owner: req.user.id });
  if (!doc) return res.status(404).json({ error: "Not found" });
  res.json(doc);
});

// Next.js: auth in every API route
export default async function handler(req, res) {
  const session = await getServerSession(req, res, authOptions);
  if (!session || session.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }
  const users = await prisma.user.findMany();
  res.json(users);
}
```

### Grep Detection Patterns

```bash
# Routes without auth middleware
grep -rn "app\.\(get\|post\|put\|delete\|patch\)(" --include="*.js" --include="*.ts" | grep -v "auth\|protect\|verify\|middleware\|session"

# IDOR - findById without owner filter
grep -rn "findById(req\.params\|findById(req\.query" --include="*.js" --include="*.ts"
grep -rn "findByPk(req\.params\|findByPk(req\.query" --include="*.js" --include="*.ts"

# Next.js API routes without auth
grep -rL "getServerSession\|getSession\|authenticate\|auth(" pages/api/**/*.ts pages/api/**/*.js app/api/**/*.ts app/api/**/*.js 2>/dev/null

# GraphQL resolvers
grep -rn "Query:\|Mutation:" --include="*.js" --include="*.ts" -A 5 | grep -v "auth\|context\.user\|isAuthenticated"
```

---

## C4: Mass Assignment

### Key Questions
- Are request bodies passed directly to ORM create/update methods?
- Is there a whitelist of allowed fields for each endpoint?
- Can users set `role`, `isAdmin`, `verified`, or other privilege fields via request body?
- Are nested or relational fields protected from mass assignment?

### Commonly Missed
- Express handlers passing `req.body` directly to Mongoose `Model.create()` or `new Model(req.body)`
- Sequelize `Model.create(req.body)` without an `attributes` or `fields` whitelist
- TypeORM `repository.save(req.body)` accepting arbitrary fields
- Prisma `prisma.user.create({ data: req.body })` without filtering input
- `Object.assign(model, req.body)` overwriting protected fields
- `findByIdAndUpdate(id, req.body)` or `findOneAndUpdate` with unfiltered body
- Nested object assignment allowing relationship manipulation (e.g., setting `organizationId`)
- TypeScript interfaces giving false confidence (runtime input is not type-checked)

### Dangerous Patterns

```javascript
// Express + Mongoose: direct body to create
app.post("/api/users", async (req, res) => {
  const user = new User(req.body);  // attacker sends { role: "admin", verified: true }
  await user.save();
  res.json(user);
});

app.post("/api/users", async (req, res) => {
  const user = await User.create(req.body);  // same issue
  res.json(user);
});

// Object.assign overwriting protected fields
app.put("/api/users/:id", authenticate, async (req, res) => {
  const user = await User.findById(req.params.id);
  Object.assign(user, req.body);  // attacker sends { role: "admin" }
  await user.save();
});

// Mongoose findByIdAndUpdate with raw body
app.put("/api/users/:id", authenticate, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body);
  // attacker sends { role: "admin", verified: true }
});

// Sequelize: create without field whitelist
app.post("/api/users", async (req, res) => {
  const user = await User.create(req.body);  // no fields option
  res.json(user);
});

// TypeORM: save with raw body
app.post("/api/users", async (req, res) => {
  const user = await userRepository.save(req.body);  // arbitrary fields persisted
  res.json(user);
});

// Prisma: unfiltered body in create
app.post("/api/users", async (req, res) => {
  const user = await prisma.user.create({ data: req.body });  // all fields accepted
  res.json(user);
});

// Spread operator mass assignment
app.put("/api/profile", authenticate, async (req, res) => {
  await prisma.user.update({
    where: { id: req.user.id },
    data: { ...req.body },  // attacker sends { role: "admin" }
  });
});
```

### Safe Alternatives

```javascript
// Whitelist allowed fields explicitly
const allowedFields = ["name", "email", "bio"];
const updates = {};
for (const field of allowedFields) {
  if (req.body[field] !== undefined) updates[field] = req.body[field];
}
await User.findByIdAndUpdate(req.params.id, updates);

// Destructure only allowed fields
const { name, email, bio } = req.body;
const user = await User.create({ name, email, bio });

// Sequelize: use fields option
const user = await User.create(req.body, {
  fields: ["name", "email", "bio"],  // only these columns are set
});

// TypeORM: pick allowed fields
const { name, email, bio } = req.body;
const user = userRepository.create({ name, email, bio });
await userRepository.save(user);

// Prisma: explicit field selection
const user = await prisma.user.create({
  data: {
    name: req.body.name,
    email: req.body.email,
    bio: req.body.bio,
  },
});

// Validation library (e.g., zod) to define allowed shape
import { z } from "zod";
const CreateUserSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  bio: z.string().optional(),
});
const data = CreateUserSchema.parse(req.body);  // strips unknown fields
const user = await User.create(data);
```

### Grep Detection Patterns

```bash
# Mongoose mass assignment
grep -rn "new.*Model(req\.body\|\.create(req\.body\|Object\.assign(.*req\.body" --include="*.js" --include="*.ts"
grep -rn "findByIdAndUpdate(.*req\.body\|findOneAndUpdate(.*req\.body" --include="*.js" --include="*.ts"

# Sequelize mass assignment (create without fields option)
grep -rn "\.create(req\.body" --include="*.js" --include="*.ts"

# TypeORM mass assignment
grep -rn "repository\.save(req\.body\|repository\.create(req\.body" --include="*.js" --include="*.ts"

# Prisma mass assignment
grep -rn "prisma\..*\.create.*req\.body\|prisma\..*\.update.*req\.body" --include="*.js" --include="*.ts"

# Spread operator mass assignment
grep -rn "\.\.\.req\.body" --include="*.js" --include="*.ts"

# Object.assign with request body
grep -rn "Object\.assign(.*req\.body" --include="*.js" --include="*.ts"
```

---

## C5: Data Exposure

### Key Questions
- Are secrets stored outside source code?
- Does `NEXT_PUBLIC_` prefix expose any secret keys?
- Are API keys or tokens visible in client-side bundles?
- Are sensitive fields excluded from API responses?

### Commonly Missed
- `NEXT_PUBLIC_SECRET_KEY` (Next.js exposes any `NEXT_PUBLIC_*` to the browser)
- `REACT_APP_API_SECRET` (Create React App exposes `REACT_APP_*` to the browser)
- `VITE_SECRET_KEY` (Vite exposes `VITE_*` to the browser)
- API responses including `password`, `passwordHash`, `token` fields
- `console.log` with request bodies containing credentials (left from debugging)
- `.env` files committed to git
- Source maps deployed to production exposing source code

### Dangerous Patterns

```javascript
// Secrets exposed to browser via framework prefixes
// .env file:
// NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_abc123  // exposed to browser!
// REACT_APP_DB_PASSWORD=mypassword               // exposed to browser!
// VITE_API_SECRET=secret123                       // exposed to browser!

// Hardcoded secrets
const apiKey = "sk-live-abc123def456";
const dbPassword = "super_secret";

// API response leaking sensitive fields
app.get("/api/users/:id", (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);  // includes passwordHash, tokens, etc.
});

// Console logging secrets
console.log("Auth token:", req.headers.authorization);
console.log("Request body:", req.body);  // may contain passwords
```

### Safe Alternatives

```javascript
// Server-only environment variables (no prefix)
// .env:
// STRIPE_SECRET_KEY=sk_live_abc123   // server only
// NEXT_PUBLIC_STRIPE_PK=pk_live_xyz  // only public key to browser

// Explicit field selection in API responses
app.get("/api/users/:id", (req, res) => {
  const user = await User.findById(req.params.id).select("id username email avatar");
  res.json(user);
});

// Mongoose: schema-level field exclusion
const userSchema = new Schema({
  password: { type: String, select: false },
  email: String,
});

// Never log request bodies in production
if (process.env.NODE_ENV !== "production") {
  console.log("Debug:", req.body);
}
```

### Grep Detection Patterns

```bash
# Exposed secrets via framework prefixes
grep -rn "NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*KEY\|NEXT_PUBLIC_.*PASSWORD" --include="*.env*"
grep -rn "REACT_APP_.*SECRET\|REACT_APP_.*KEY\|REACT_APP_.*PASSWORD" --include="*.env*"
grep -rn "VITE_.*SECRET\|VITE_.*KEY\|VITE_.*PASSWORD" --include="*.env*"

# Hardcoded secrets
grep -rn "apiKey\s*=\s*[\"']" --include="*.js" --include="*.ts"
grep -rn "secret\s*=\s*[\"']" --include="*.js" --include="*.ts"
grep -rn "password\s*=\s*[\"']" --include="*.js" --include="*.ts"

# Console logging sensitive data
grep -rn "console\.log.*password\|console\.log.*token\|console\.log.*secret\|console\.log.*authorization" --include="*.js" --include="*.ts" -i

# Source maps in production
find . -name "*.map" -path "*/build/*" -o -name "*.map" -path "*/dist/*"

# .env in git
git ls-files | grep "\.env"
```

---

## C6: Misconfiguration

### Key Questions
- Is `NODE_ENV` set to `production` in production?
- Are verbose error messages disabled?
- Is `helmet.js` or equivalent security headers middleware used?
- Is CORS configured restrictively?
- Are development tools/routes disabled?

### Commonly Missed
- Express default error handler showing stack traces
- Missing `helmet()` middleware
- CORS `origin: "*"` or `origin: true`
- GraphQL introspection enabled in production
- Swagger/API docs exposed in production
- `X-Powered-By: Express` header not removed

### Dangerous Patterns

```javascript
// Verbose errors in production
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// No helmet
// (just missing app.use(helmet()))

// CORS wide open
app.use(cors({ origin: "*" }));
app.use(cors({ origin: true }));
app.use(cors());  // defaults to reflect origin

// GraphQL introspection in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,  // should be false in production
  playground: true,       // should be false in production
});

// Express exposing framework info
// X-Powered-By: Express header is sent by default

// Development routes in production
app.get("/debug/env", (req, res) => res.json(process.env));
```

### Safe Alternatives

```javascript
// Production error handler
app.use((err, req, res, next) => {
  console.error(err);  // log for debugging
  res.status(500).json({ error: "Internal server error" });
});

// Helmet for security headers
const helmet = require("helmet");
app.use(helmet());
app.disable("x-powered-by");

// Restrictive CORS
app.use(cors({
  origin: ["https://myapp.example.com"],
  methods: ["GET", "POST"],
  credentials: true,
}));

// GraphQL: disable introspection in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== "production",
  plugins: [
    process.env.NODE_ENV === "production"
      ? ApolloServerPluginLandingPageDisabled()
      : ApolloServerPluginLandingPageLocalDefault(),
  ],
});
```

### Grep Detection Patterns

```bash
# Verbose errors
grep -rn "err\.stack\|error\.stack" --include="*.js" --include="*.ts" | grep "res\.\|json\|send"

# Missing helmet
grep -rn "helmet" --include="*.js" --include="*.ts"  # should find usage

# CORS
grep -rn 'origin:\s*"\*"\|origin:\s*true\|cors()' --include="*.js" --include="*.ts"

# GraphQL introspection
grep -rn "introspection:\s*true\|playground:\s*true" --include="*.js" --include="*.ts"

# Debug routes
grep -rn "/debug\|/test/\|/dev/" --include="*.js" --include="*.ts" | grep "app\.\|router\."

# X-Powered-By
grep -rn "x-powered-by\|disable.*x-powered" --include="*.js" --include="*.ts"
```

---

## C7: XSS (Cross-Site Scripting)

### Key Questions
- Is `innerHTML`, `dangerouslySetInnerHTML`, or `v-html` used with user data?
- Is `document.write` or `document.writeln` used?
- Are CSP headers configured?
- Is user input reflected in HTML attributes without encoding?
- Are server-rendered templates escaping output?

### Commonly Missed
- React `dangerouslySetInnerHTML={{ __html: userContent }}`
- Vue `v-html="userContent"`
- Angular `[innerHTML]="userContent"` bypassing DomSanitizer
- jQuery `$(element).html(userInput)`
- EJS `<%- userInput %>` (unescaped) vs `<%= userInput %>` (escaped)
- Handlebars `{{{ userInput }}}` (triple braces = unescaped)
- URL-based XSS: `<a href={userInput}>` where input is `javascript:alert(1)`

### Dangerous Patterns

```javascript
// React
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// Vue
<div v-html="userContent"></div>

// Angular (bypassing sanitizer)
this.sanitizer.bypassSecurityTrustHtml(userContent);

// Vanilla JS
element.innerHTML = userInput;
document.write(userInput);
document.getElementById("output").outerHTML = userInput;

// jQuery
$(selector).html(userInput);
$(selector).append(userInput);

// EJS unescaped
// <%- userInput %>

// Handlebars unescaped
// {{{ userInput }}}

// Pug unescaped
// !{userInput}

// URL-based XSS
<a href={userInput}>Click here</a>  // userInput = "javascript:alert(1)"

// DOM XSS via URL fragment
const data = window.location.hash.slice(1);
document.getElementById("output").innerHTML = data;
```

### Safe Alternatives

```javascript
// React: render text content (auto-escaped)
<div>{userContent}</div>
// If HTML rendering is needed, use DOMPurify
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />

// Vue: use text interpolation
<div>{{ userContent }}</div>

// Vanilla JS: use textContent
element.textContent = userInput;

// EJS: use escaped output
// <%= userInput %>

// Handlebars: use double braces (escaped)
// {{ userInput }}

// URL validation
const isValidUrl = (url) => {
  try {
    const parsed = new URL(url);
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
};

// CSP header
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
  },
}));
```

### Grep Detection Patterns

```bash
# React XSS
grep -rn "dangerouslySetInnerHTML" --include="*.jsx" --include="*.tsx" --include="*.js" --include="*.ts"

# Vue XSS
grep -rn "v-html" --include="*.vue"

# Angular XSS
grep -rn "bypassSecurityTrust" --include="*.ts"
grep -rn '\[innerHTML\]' --include="*.html" --include="*.ts"

# Vanilla JS / jQuery XSS
grep -rn "\.innerHTML\s*=" --include="*.js" --include="*.ts"
grep -rn "document\.write(" --include="*.js" --include="*.ts"
grep -rn '\.html(' --include="*.js" --include="*.ts"

# Template XSS
grep -rn "<%- " --include="*.ejs"
grep -rn "{{{" --include="*.hbs" --include="*.handlebars"
grep -rn "!{" --include="*.pug"

# URL-based XSS
grep -rn 'href={' --include="*.jsx" --include="*.tsx" | grep -v "http\|#\|/"
```

---

## C8: Dependencies

### Key Questions
- Has `npm audit` or `yarn audit` been run?
- Are there pinned versions with known CVEs?
- Are any dependencies end-of-life?
- Is `package-lock.json` or `yarn.lock` committed and up to date?

### Commonly Missed
- Transitive dependencies with vulnerabilities
- `lodash` prototype pollution in older versions (< 4.17.21)
- `express` older versions with various CVEs
- `node-fetch` < 2.6.7 (redirect credential leak)
- `jsonwebtoken` < 9.0.0 (algorithm confusion)
- `axios` < 1.6.0 (SSRF via redirects)
- Dev dependencies that end up in production builds

### High-Risk Packages to Check

| Package | Risk | Check for |
|---------|------|-----------|
| express | Multiple CVEs per year | Version currency |
| lodash | < 4.17.21 prototype pollution | CVE-2021-23337 |
| jsonwebtoken | < 9.0.0 algorithm confusion | Version check |
| axios | < 1.6.0 SSRF | Version check |
| node-fetch | < 2.6.7 credential leak | Version check |
| minimist | < 1.2.6 prototype pollution | Often transitive |
| qs | < 6.10.3 prototype pollution | Often transitive |
| socket.io | Various CVEs | Version check |
| next | Multiple CVEs per year | Version currency |
| angular | EOL versions (AngularJS) | Framework version |

### Grep Detection Patterns

```bash
# Run audit
npm audit
yarn audit

# Check for known vulnerable versions in lockfile
grep -n "lodash" package-lock.json | head -5
grep -n "jsonwebtoken" package-lock.json | head -5

# Check for wildcard or very loose version ranges
grep -rn '"*"\|"latest"\|">=' package.json

# Check for unnecessary dependencies
grep -rn "devDependencies" package.json -A 50 | grep "webpack\|babel" # should not be in production

# Check Node.js version
grep -rn "engines" package.json -A 3
node --version  # check against EOL list
```

---

## C9: Cryptography

### Key Questions
- Is `crypto.randomBytes` or `crypto.randomUUID` used for tokens (not `Math.random`)?
- Is `bcrypt` or `argon2` used for password hashing?
- Is TLS enforced for all connections?
- Are encryption keys stored securely?

### Commonly Missed
- `Math.random()` for session IDs, tokens, or OTP codes
- `crypto.createHash("md5")` for password hashing
- Hardcoded encryption keys in source code
- Missing `NODE_TLS_REJECT_UNAUTHORIZED=0` in environment (disables TLS)
- `uuid` v1 (time-based, predictable) used for security tokens
- Web Crypto API misuse on the client side

### Dangerous Patterns

```javascript
// Weak random
const token = Math.random().toString(36).substring(2);
const otp = Math.floor(Math.random() * 1000000);
const sessionId = Math.random().toString(16).slice(2);

// Weak password hashing
const crypto = require("crypto");
const hash = crypto.createHash("md5").update(password).digest("hex");
const hash = crypto.createHash("sha256").update(password).digest("hex");  // no salt

// Hardcoded key
const encryptionKey = "my-secret-key-1234567890123456";
const iv = Buffer.from("1234567890123456");  // static IV

// Disabled TLS verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// UUID v1 for security tokens (predictable)
const { v1: uuidv1 } = require("uuid");
const resetToken = uuidv1();  // time-based, guessable
```

### Safe Alternatives

```javascript
// Cryptographically secure random
const crypto = require("crypto");
const token = crypto.randomBytes(32).toString("hex");
const otp = crypto.randomInt(100000, 999999);
const sessionId = crypto.randomUUID();

// Strong password hashing
const bcrypt = require("bcrypt");
const hash = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(password, hash);

// Or argon2
const argon2 = require("argon2");
const hash = await argon2.hash(password);
const isValid = await argon2.verify(hash, password);

// AES-256-GCM with random IV
const key = crypto.randomBytes(32);  // store securely
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

// UUID v4 for tokens (cryptographic random)
const { v4: uuidv4 } = require("uuid");
const resetToken = uuidv4();
```

### Grep Detection Patterns

```bash
# Weak random
grep -rn "Math\.random()" --include="*.js" --include="*.ts" | grep -i "token\|secret\|key\|session\|otp\|code\|id\|password"

# Weak hashing
grep -rn "createHash.*md5\|createHash.*sha1" --include="*.js" --include="*.ts"
grep -rn "createHash.*sha256" --include="*.js" --include="*.ts" | grep -i "password"

# Hardcoded keys
grep -rn "encryptionKey\s*=\s*[\"']\|secretKey\s*=\s*[\"']" --include="*.js" --include="*.ts"

# Disabled TLS
grep -rn "NODE_TLS_REJECT_UNAUTHORIZED" --include="*.js" --include="*.ts" --include="*.env*"
grep -rn "rejectUnauthorized:\s*false" --include="*.js" --include="*.ts"

# UUID v1 for security
grep -rn "uuidv1\|uuid\.v1\|v1()" --include="*.js" --include="*.ts" | grep -i "token\|session\|reset"
```

---

## C10: SSRF (Server-Side Request Forgery)

### Key Questions
- Does the application make HTTP requests to URLs derived from user input?
- Are webhook or callback URLs validated before use?
- Does the application render PDFs or images from user-supplied URLs or HTML?
- Are internal/cloud metadata endpoints accessible from server-side requests?
- Does the application proxy or fetch resources on behalf of users?

### Commonly Missed
- `fetch(userUrl)` or `axios.get(userUrl)` without URL validation
- Webhook/callback URL registration allowing internal network targets
- Puppeteer/Playwright `page.goto(userUrl)` navigating to internal services
- PDF generation (puppeteer, html-pdf, wkhtmltopdf) rendering user-controlled HTML containing `<img>`, `<link>`, `<iframe>` tags with internal URLs
- Image proxy or resize endpoints fetching arbitrary URLs
- Cloud metadata endpoint (`http://169.254.169.254/latest/meta-data/`) reachable via SSRF
- DNS rebinding attacks bypassing hostname validation
- Redirect-based SSRF (initial URL passes validation, but redirects to internal host)
- URL parsing differences between validation library and HTTP client

### Dangerous Patterns

```javascript
// Direct fetch with user-controlled URL
app.get("/api/preview", async (req, res) => {
  const response = await fetch(req.query.url);  // attacker: ?url=http://169.254.169.254/latest/meta-data/
  const body = await response.text();
  res.json({ content: body });
});

// Axios with user URL
app.post("/api/webhook/test", async (req, res) => {
  const result = await axios.get(req.body.callbackUrl);  // internal network scan
  res.json({ status: result.status });
});

// Node http module
const http = require("http");
http.get(userUrl, (resp) => { /* ... */ });

// got library
const got = require("got");
const response = await got(userUrl);

// Webhook/callback URL stored and called later
app.post("/api/webhooks", async (req, res) => {
  await Webhook.create({ url: req.body.url });  // no validation
});
// Later: fetch(webhook.url) hits internal services

// Puppeteer navigating to user URL
app.get("/api/screenshot", async (req, res) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto(req.query.url);  // can access internal network, file:// protocol
  const screenshot = await page.screenshot();
  res.type("png").send(screenshot);
});

// Playwright with user URL
await page.goto(userProvidedUrl);  // same risks as Puppeteer

// PDF generation with user-controlled HTML
app.post("/api/generate-pdf", async (req, res) => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.setContent(req.body.html);  // HTML may contain <img src="http://169.254.169.254/...">
  const pdf = await page.pdf();
  res.type("pdf").send(pdf);
});

// html-pdf with user content
const pdf = require("html-pdf");
pdf.create(req.body.html).toBuffer((err, buffer) => {  // renders external resources in HTML
  res.type("pdf").send(buffer);
});

// Image proxy endpoint
app.get("/api/image-proxy", async (req, res) => {
  const imageUrl = req.query.src;
  const response = await fetch(imageUrl);  // fetches any URL including internal
  const buffer = await response.buffer();
  res.type(response.headers.get("content-type")).send(buffer);
});
```

### Safe Alternatives

```javascript
// URL validation with allowlist
const { URL } = require("url");

function isAllowedUrl(input) {
  try {
    const parsed = new URL(input);
    // Only allow http(s) protocols
    if (!["http:", "https:"].includes(parsed.protocol)) return false;
    // Block internal/private IPs
    const hostname = parsed.hostname;
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname.startsWith("10.") ||
      hostname.startsWith("172.") ||
      hostname.startsWith("192.168.") ||
      hostname === "169.254.169.254" ||
      hostname.startsWith("169.254.") ||
      hostname === "[::1]" ||
      hostname.endsWith(".internal") ||
      hostname.endsWith(".local")
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

// Validate before fetching
app.get("/api/preview", async (req, res) => {
  if (!isAllowedUrl(req.query.url)) {
    return res.status(400).json({ error: "URL not allowed" });
  }
  const response = await fetch(req.query.url, { redirect: "error" });  // block redirects
  const body = await response.text();
  res.json({ content: body });
});

// DNS resolution check (prevents DNS rebinding)
const dns = require("dns").promises;
async function resolveAndValidate(urlString) {
  const parsed = new URL(urlString);
  const { address } = await dns.lookup(parsed.hostname);
  const ipParts = address.split(".");
  if (
    address === "127.0.0.1" ||
    ipParts[0] === "10" ||
    (ipParts[0] === "172" && parseInt(ipParts[1]) >= 16 && parseInt(ipParts[1]) <= 31) ||
    (ipParts[0] === "192" && ipParts[1] === "168") ||
    address.startsWith("169.254.")
  ) {
    throw new Error("Internal IP not allowed");
  }
  return urlString;
}

// Webhook URL domain allowlist
const ALLOWED_WEBHOOK_DOMAINS = ["hooks.slack.com", "discord.com", "api.pagerduty.com"];
function isAllowedWebhookUrl(url) {
  const parsed = new URL(url);
  return ALLOWED_WEBHOOK_DOMAINS.some((d) => parsed.hostname === d || parsed.hostname.endsWith(`.${d}`));
}

// Puppeteer with URL validation and sandboxing
app.get("/api/screenshot", async (req, res) => {
  if (!isAllowedUrl(req.query.url)) {
    return res.status(400).json({ error: "URL not allowed" });
  }
  const browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-dev-shm-usage"] });
  const page = await browser.newPage();
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    const reqUrl = request.url();
    if (!isAllowedUrl(reqUrl)) {
      request.abort();
    } else {
      request.continue();
    }
  });
  await page.goto(req.query.url);
  const screenshot = await page.screenshot();
  await browser.close();
  res.type("png").send(screenshot);
});

// PDF generation: sanitize HTML to remove external resource references
const sanitizeHtml = require("sanitize-html");
const cleanHtml = sanitizeHtml(req.body.html, {
  allowedTags: sanitizeHtml.defaults.allowedTags,
  allowedAttributes: {},  // strip src, href, etc.
});
```

### Grep Detection Patterns

```bash
# Direct user URL in fetch/axios/http/got
grep -rn "fetch(req\.\|fetch(.*userUrl\|fetch(.*url)" --include="*.js" --include="*.ts"
grep -rn "axios\.\(get\|post\|put\|delete\|request\)(req\.\|axios.*userUrl\|axios.*\.url" --include="*.js" --include="*.ts"
grep -rn "http\.get(.*req\.\|http\.request(.*req\.\|https\.get(.*req\.\|https\.request(.*req\." --include="*.js" --include="*.ts"
grep -rn "got(req\.\|got(.*userUrl\|got(.*\.url" --include="*.js" --include="*.ts"

# Puppeteer/Playwright SSRF
grep -rn "page\.goto(req\.\|page\.goto(.*userUrl\|page\.goto(.*\.url" --include="*.js" --include="*.ts"
grep -rn "page\.setContent(req\.\|page\.setContent(.*body" --include="*.js" --include="*.ts"

# PDF generation with user content
grep -rn "html-pdf\|puppeteer.*pdf\|wkhtmltopdf\|pdf\.create(" --include="*.js" --include="*.ts"

# Image proxy
grep -rn "image.*proxy\|img.*proxy\|/proxy" --include="*.js" --include="*.ts" | grep -i "fetch\|axios\|get\|request"

# Webhook/callback URLs
grep -rn "callbackUrl\|webhookUrl\|webhook\.url\|callback_url" --include="*.js" --include="*.ts"

# Cloud metadata access
grep -rn "169\.254\.169\.254\|metadata\.google\|metadata\.azure" --include="*.js" --include="*.ts"
```

---

## C11: Logging & Monitoring

### Key Questions
- Are passwords, tokens, or API keys logged anywhere?
- Is PII logged without masking?
- Are authentication events logged?
- Is log injection possible via user input?

### Commonly Missed
- `console.log(req.body)` including passwords
- `console.log(req.headers)` including authorization tokens
- Morgan or Winston logging full request bodies
- Error tracking (Sentry, Datadog) capturing sensitive form data
- Server-side rendering logging user data in HTML generation
- Log injection via newlines in user input

### Dangerous Patterns

```javascript
// Logging passwords
console.log("Login attempt:", req.body);  // includes password field
console.log("User created:", user);       // includes password hash

// Logging tokens
console.log("Headers:", req.headers);     // includes Authorization
console.log("API key:", apiKey);

// Morgan logging body
app.use(morgan(":method :url :body"));  // custom format including body

// Winston logging everything
logger.info("Request received", { body: req.body, headers: req.headers });

// Error tracking with PII
Sentry.captureException(error, { extra: { user: req.body } });

// Log injection
logger.info(`User login: ${req.body.username}`);
// Username = "admin\n[INFO] Payment processed: $10000"
```

### Safe Alternatives

```javascript
// Log only non-sensitive fields
console.log("Login attempt:", { username: req.body.username });  // no password

// Structured logging with field filtering
const logger = winston.createLogger({
  format: winston.format.combine(
    filterSensitiveFields(),
    winston.format.json()
  ),
});

function filterSensitiveFields() {
  const sensitiveKeys = ["password", "token", "secret", "authorization", "cookie"];
  return winston.format((info) => {
    for (const key of sensitiveKeys) {
      if (info[key]) info[key] = "[REDACTED]";
    }
    return info;
  })();
}

// Sentry: filter sensitive data
Sentry.init({
  beforeSend(event) {
    if (event.request?.data) {
      delete event.request.data.password;
      delete event.request.data.token;
    }
    return event;
  },
});

// Prevent log injection
const safeUsername = req.body.username.replace(/[\n\r]/g, "");
logger.info("User login", { username: safeUsername });
```

### Grep Detection Patterns

```bash
# Console.log with sensitive data
grep -rn "console\.log.*req\.body\|console\.log.*req\.headers" --include="*.js" --include="*.ts"
grep -rn "console\.log.*password\|console\.log.*token\|console\.log.*secret\|console\.log.*apiKey" --include="*.js" --include="*.ts" -i

# Winston/Pino/Bunyan logging sensitive data
grep -rn "logger\.\(info\|debug\|warn\|error\).*req\.body\|logger.*req\.headers" --include="*.js" --include="*.ts"

# Sentry PII
grep -rn "captureException\|captureMessage" --include="*.js" --include="*.ts" | grep "req\.\|user\.\|body"

# Leftover console statements
grep -rn "console\.log(" --include="*.js" --include="*.ts" | grep -v "test\|spec\|__test__\|node_modules"
```

---

## C12: Infrastructure (IaC)

### Key Questions
- Does the container run as non-root?
- Are secrets passed via environment variables (not in Dockerfiles)?
- Are images pinned to specific versions?
- Are serverless function permissions minimized (least privilege)?
- Is the Node.js production build properly configured?

### Commonly Missed
- `Dockerfile` missing `USER` directive
- `node:latest` instead of pinned slim image
- `npm install` instead of `npm ci --omit=dev` in production
- Secrets in `docker-compose.yml` committed to git
- AWS Lambda with `*` IAM permissions
- Vercel/Netlify environment variables exposed to preview deployments
- `serverless.yml` with overly broad IAM statements

### Dangerous Patterns

```dockerfile
# Running as root with full dependencies
FROM node:latest
WORKDIR /app
COPY . .
RUN npm install
ENV API_KEY=sk-live-abc123
CMD ["node", "server.js"]
```

```yaml
# docker-compose.yml with secrets
services:
  app:
    environment:
      - DB_PASSWORD=mysecret
      - API_KEY=sk-live-abc123
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # container escape risk
```

```yaml
# serverless.yml with broad permissions
provider:
  iam:
    role:
      statements:
        - Effect: Allow
          Action: "*"
          Resource: "*"
```

### Safe Alternatives

```dockerfile
# Multi-stage, non-root, pinned, production-only deps
FROM node:20.11-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:20.11-slim
RUN groupadd -r appuser && useradd -r -g appuser appuser
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY . .
USER appuser
EXPOSE 3000
HEALTHCHECK CMD ["node", "-e", "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"]
CMD ["node", "server.js"]
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
          memory: 512M
          cpus: "0.5"
```

```yaml
# serverless.yml with least privilege
provider:
  iam:
    role:
      statements:
        - Effect: Allow
          Action:
            - dynamodb:GetItem
            - dynamodb:PutItem
          Resource: "arn:aws:dynamodb:us-east-1:*:table/MyTable"
```

### Grep Detection Patterns

```bash
# Dockerfile issues
grep -rn "FROM.*latest" Dockerfile*
grep -rn "^ENV.*PASSWORD\|^ENV.*SECRET\|^ENV.*KEY\|^ENV.*TOKEN" Dockerfile*
grep -n "USER" Dockerfile*  # check if USER directive exists
grep -rn "npm install" Dockerfile* | grep -v "ci\|--omit"

# Docker-compose secrets
grep -rn "PASSWORD\|SECRET\|KEY\|TOKEN" docker-compose*.yml | grep -v "#"
grep -rn "docker\.sock" docker-compose*.yml

# Serverless broad permissions
grep -rn 'Action:\s*"\*"\|Resource:\s*"\*"' --include="*.yml" --include="*.yaml"
grep -rn "AdministratorAccess\|PowerUserAccess" --include="*.yml" --include="*.yaml"

# Kubernetes
grep -rn "privileged:\s*true" --include="*.yml" --include="*.yaml"
grep -rn "runAsUser:\s*0\|runAsRoot" --include="*.yml" --include="*.yaml"
grep -rn "hostNetwork:\s*true" --include="*.yml" --include="*.yaml"
```
