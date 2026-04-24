# Express.js/Node.js Web Framework - Security Vulnerability Reference

## Identification Features

```bash
# Detect Express usage
grep -r "require.*express\|from.*express" --include="*.js" --include="*.ts" --include="*.mjs"
grep -r "express()" --include="*.js" --include="*.ts"
grep -r "\"express\"" package.json
grep -r "app\.listen\|app\.use\|app\.get\|app\.post" --include="*.js" --include="*.ts"
```

Common file patterns: `app.js`, `server.js`, `index.js`, `routes/` directory, `middleware/` directory.

---

## Critical Vulnerabilities

### 1. eval() with User Input - Remote Code Execution

Using `eval()`, `Function()`, or `vm` module with user-controlled data allows arbitrary code execution.

**Dangerous:**
```javascript
// eval with user input
app.get('/calc', (req, res) => {
  const expr = req.query.expression;
  const result = eval(expr); // RCE: ?expression=require('child_process').execSync('id')
  res.send(`Result: ${result}`);
});

// new Function with user input
app.post('/template', (req, res) => {
  const fn = new Function('data', req.body.code);
  res.send(fn(data));
});

// vm module is NOT a sandbox
const vm = require('vm');
app.post('/run', (req, res) => {
  const result = vm.runInNewContext(req.body.code);
  res.send(result);
});
```

**Safe:**
```javascript
// Use a safe math parser instead of eval
const mathjs = require('mathjs');

app.get('/calc', (req, res) => {
  try {
    const expr = req.query.expression;
    const result = mathjs.evaluate(expr);
    res.send(`Result: ${result}`);
  } catch (e) {
    res.status(400).send('Invalid expression');
  }
});
```

**Detection:**
```bash
grep -rn "eval(" --include="*.js" --include="*.ts"
grep -rn "new Function(" --include="*.js" --include="*.ts"
grep -rn "vm\.run\|vm\.createContext\|vm\.Script" --include="*.js" --include="*.ts"
grep -rn "setTimeout(.*req\|setInterval(.*req" --include="*.js" --include="*.ts"
```

### 2. Command Injection via child_process

Passing user input to shell commands.

**Dangerous:**
```javascript
const { exec, execSync } = require('child_process');

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // Attacker: ?host=google.com;cat /etc/passwd
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

app.get('/lookup', (req, res) => {
  const output = execSync('nslookup ' + req.query.domain);
  res.send(output);
});
```

**Safe:**
```javascript
const { execFile } = require('child_process');
const validator = require('validator');

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // Validate input
  if (!validator.isFQDN(host) && !validator.isIP(host)) {
    return res.status(400).send('Invalid host');
  }
  // Use execFile (no shell interpolation)
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    res.send(stdout);
  });
});
```

**Detection:**
```bash
grep -rn "child_process\|exec(\|execSync\|spawn(" --include="*.js" --include="*.ts"
grep -rn "exec(.*req\.\|exec(.*\`\|execSync(.*req\.\|execSync(.*\`" --include="*.js" --include="*.ts"
grep -rn "shell:.*true\|shell:\s*true" --include="*.js" --include="*.ts"
```

### 3. Prototype Pollution

Merging or assigning user-controlled objects can modify `Object.prototype`, leading to privilege escalation or RCE.

**Dangerous:**
```javascript
// Deep merge without protection
const merge = require('lodash').merge;

app.post('/settings', (req, res) => {
  // Attacker sends: {"__proto__": {"isAdmin": true}}
  merge(userSettings, req.body);
  res.send('Updated');
});

// Manual recursive merge
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key]; // Pollutes prototype via __proto__
    }
  }
  return target;
}
```

**Safe:**
```javascript
// Use Object.create(null) for config objects
const config = Object.create(null);

// Validate keys in merge operations
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue; // Skip dangerous keys
    }
    if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
      target[key] = safeMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Or use Map instead of plain objects for user data
const userSettings = new Map();
```

**Detection:**
```bash
grep -rn "merge(\|assign(\|extend(\|deepMerge\|deepExtend" --include="*.js" --include="*.ts"
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts"
grep -rn "Object\.assign(.*req\.\|\.merge(.*req\." --include="*.js" --include="*.ts"
grep -rn "for.*in.*req\.body\|for.*in.*req\.query" --include="*.js" --include="*.ts"
```

### 4. Node.js Debug Inspector in Production

Running Node.js with `--inspect` in production exposes Chrome DevTools protocol for RCE.

**Dangerous:**
```bash
# In Dockerfile or start script
node --inspect=0.0.0.0:9229 app.js
node --inspect-brk app.js

# In package.json
"scripts": {
  "start": "node --inspect app.js"
}
```

**Safe:**
```bash
# Production: no inspect flag
node app.js

# Only in development with localhost binding
node --inspect=127.0.0.1:9229 app.js
```

**Detection:**
```bash
grep -rn "\-\-inspect" package.json Dockerfile docker-compose.yml Procfile
grep -rn "\-\-inspect" --include="*.sh" --include="*.yaml" --include="*.yml"
grep -rn "NODE_OPTIONS.*inspect" --include="*.env" --include="*.sh"
```

---

## High Vulnerabilities

### 5. SQL Injection (String Concatenation)

**Dangerous:**
```javascript
// MySQL
const mysql = require('mysql');

app.get('/user', (req, res) => {
  const id = req.query.id;
  connection.query('SELECT * FROM users WHERE id = ' + id, (err, rows) => {
    res.json(rows);
  });
  // Also dangerous
  connection.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
});

// PostgreSQL
const { Client } = require('pg');
client.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);
```

**Safe:**
```javascript
// MySQL - parameterized queries
connection.query('SELECT * FROM users WHERE id = ?', [req.query.id], (err, rows) => {
  res.json(rows);
});

// PostgreSQL - parameterized queries
client.query('SELECT * FROM users WHERE email = $1', [req.body.email]);

// Knex.js query builder
const user = await knex('users').where({ id: req.query.id }).first();

// Sequelize ORM
const user = await User.findOne({ where: { id: req.query.id } });
```

**Detection:**
```bash
grep -rn "query(.*\`.*\${\|query(.*+.*req\.\|query(.*concat" --include="*.js" --include="*.ts"
grep -rn "query(.*req\.query\|query(.*req\.body\|query(.*req\.params" --include="*.js" --include="*.ts" | grep -v "?\|\\$[0-9]"
```

### 6. NoSQL Injection (MongoDB)

**Dangerous:**
```javascript
const { MongoClient } = require('mongodb');

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // Attacker sends: {"username": {"$gt": ""}, "password": {"$gt": ""}}
  const user = await db.collection('users').findOne({
    username: username,
    password: password
  });
  if (user) res.send('Logged in');
});

// $where injection
app.get('/search', async (req, res) => {
  const results = await db.collection('items').find({
    $where: `this.name == '${req.query.name}'`
  });
});
```

**Safe:**
```javascript
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // Ensure inputs are strings, not objects
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).send('Invalid input');
  }
  const user = await db.collection('users').findOne({
    username: username,
    password: password  // Should also be hashed
  });
});

// Use mongo-sanitize to strip $ operators
const sanitize = require('mongo-sanitize');
const cleanInput = sanitize(req.body);
```

**Detection:**
```bash
grep -rn "\$where\|\$regex\|\$ne\|\$gt\|\$lt" --include="*.js" --include="*.ts"
grep -rn "findOne(.*req\.body\|find(.*req\.body\|findOneAndUpdate(.*req\.body" --include="*.js" --include="*.ts"
grep -rn "mongo-sanitize\|express-mongo-sanitize" package.json
```

### 7. Server-Side Request Forgery (SSRF)

**Dangerous:**
```javascript
const axios = require('axios');
const fetch = require('node-fetch');

app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  // Attacker: ?url=http://169.254.169.254/latest/meta-data/
  const response = await axios.get(url);
  res.send(response.data);
});

app.post('/webhook', async (req, res) => {
  const { callback_url } = req.body;
  await fetch(callback_url, { method: 'POST', body: JSON.stringify(data) });
});
```

**Safe:**
```javascript
const { URL } = require('url');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

const ALLOWED_PROTOCOLS = ['http:', 'https:'];
const BLOCKED_HOSTS = ['metadata.google.internal', '169.254.169.254'];

async function isSafeUrl(urlString) {
  const parsed = new URL(urlString);
  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) return false;
  if (BLOCKED_HOSTS.includes(parsed.hostname)) return false;
  // Resolve DNS and check for private IPs
  const addresses = await dns.resolve4(parsed.hostname);
  for (const addr of addresses) {
    const ip = ipaddr.parse(addr);
    if (ip.range() !== 'unicast') return false;
  }
  return true;
}

app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  if (!(await isSafeUrl(url))) {
    return res.status(403).send('URL not allowed');
  }
  const response = await axios.get(url, { timeout: 5000, maxRedirects: 0 });
  res.send(response.data);
});
```

**Detection:**
```bash
grep -rn "axios\.\|node-fetch\|got(\|request(\|undici\|fetch(" --include="*.js" --include="*.ts" | grep -i "req\.\|query\.\|body\.\|params\."
grep -rn "http\.get(.*req\|https\.get(.*req" --include="*.js" --include="*.ts"
```

### 8. Path Traversal

**Dangerous:**
```javascript
const path = require('path');
const fs = require('fs');

app.get('/file', (req, res) => {
  const filename = req.query.name;
  // Attacker: ?name=../../../etc/passwd
  const filepath = path.join(__dirname, 'uploads', filename);
  res.sendFile(filepath);
});

app.get('/download/:file', (req, res) => {
  fs.readFile('./public/' + req.params.file, (err, data) => {
    res.send(data);
  });
});
```

**Safe:**
```javascript
const path = require('path');

const UPLOAD_DIR = path.resolve(__dirname, 'uploads');

app.get('/file', (req, res) => {
  const filename = req.query.name;
  const filepath = path.resolve(UPLOAD_DIR, filename);
  // Verify the resolved path is within the upload directory
  if (!filepath.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(403).send('Access denied');
  }
  res.sendFile(filepath);
});
```

**Detection:**
```bash
grep -rn "sendFile(.*req\.\|readFile(.*req\.\|createReadStream(.*req\." --include="*.js" --include="*.ts"
grep -rn "path\.join(.*req\.\|path\.resolve(.*req\." --include="*.js" --include="*.ts"
grep -rn "fs\.\|readFileSync\|writeFileSync" --include="*.js" --include="*.ts" | grep "req\."
```

### 9. JWT Vulnerabilities

**Dangerous:**
```javascript
const jwt = require('jsonwebtoken');

// Weak secret
const SECRET = 'mysecret';

// No algorithm restriction
app.get('/verify', (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  const decoded = jwt.verify(token, SECRET); // Accepts any algorithm
  res.json(decoded);
});

// No expiry
const token = jwt.sign({ userId: user.id }, SECRET);

// Secret from token header (alg confusion)
const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64'));
jwt.verify(token, header.alg === 'HS256' ? SECRET : publicKey);
```

**Safe:**
```javascript
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET; // Strong secret from env

// Sign with expiry
const token = jwt.sign(
  { userId: user.id, iss: 'myapp' },
  SECRET,
  { algorithm: 'HS256', expiresIn: '1h' }
);

// Verify with fixed algorithm
const decoded = jwt.verify(token, SECRET, {
  algorithms: ['HS256'],
  issuer: 'myapp',
  complete: true
});
```

**Detection:**
```bash
grep -rn "jwt\.sign\|jwt\.verify\|jwt\.decode" --include="*.js" --include="*.ts"
grep -rn "algorithms:" --include="*.js" --include="*.ts" | grep -i jwt
grep -rn "expiresIn\|exp:" --include="*.js" --include="*.ts" | grep -i jwt
```

---

## Medium Vulnerabilities

### 10. XSS via res.send() Without Encoding

**Dangerous:**
```javascript
app.get('/search', (req, res) => {
  const query = req.query.q;
  // Reflected XSS
  res.send(`<h1>Results for: ${query}</h1>`);
});

app.get('/user/:name', (req, res) => {
  res.send(`<p>Hello ${req.params.name}</p>`);
});
```

**Safe:**
```javascript
const escapeHtml = require('escape-html');

app.get('/search', (req, res) => {
  const query = escapeHtml(req.query.q);
  res.send(`<h1>Results for: ${query}</h1>`);
});

// Better: use a template engine with auto-escaping
app.set('view engine', 'ejs');
app.get('/search', (req, res) => {
  res.render('search', { query: req.query.q }); // EJS auto-escapes
});
```

**Detection:**
```bash
grep -rn "res\.send(.*\`.*req\.\|res\.send(.*\`.*\$\{" --include="*.js" --include="*.ts"
grep -rn "res\.write(.*req\.\|res\.end(.*req\." --include="*.js" --include="*.ts"
grep -rn "innerHTML\|outerHTML\|document\.write" --include="*.js" --include="*.ts" --include="*.ejs"
```

### 11. Missing helmet.js Security Headers

**Dangerous:**
```javascript
// No security headers set
const app = express();
app.use(express.json());
// Missing helmet()
```

**Safe:**
```javascript
const helmet = require('helmet');

const app = express();
app.use(helmet());
// Sets: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security,
//       X-XSS-Protection, Content-Security-Policy, etc.

// Or configure individually
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true }
}));
```

**Detection:**
```bash
grep -rn "helmet" package.json
grep -rn "require.*helmet\|import.*helmet\|app\.use(.*helmet" --include="*.js" --include="*.ts"
grep -rn "X-Frame-Options\|Content-Security-Policy\|Strict-Transport" --include="*.js" --include="*.ts"
```

### 12. CORS Wildcard Configuration

**Dangerous:**
```javascript
const cors = require('cors');
app.use(cors()); // Allows all origins

app.use(cors({
  origin: '*',
  credentials: true // Wildcard + credentials = dangerous
}));

// Manual header
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin); // Reflects origin
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
```

**Safe:**
```javascript
const cors = require('cors');

const allowedOrigins = ['https://myapp.com', 'https://admin.myapp.com'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

**Detection:**
```bash
grep -rn "cors(" --include="*.js" --include="*.ts"
grep -rn "Access-Control-Allow-Origin.*\*\|Access-Control-Allow-Origin.*origin" --include="*.js" --include="*.ts"
grep -rn "credentials.*true" --include="*.js" --include="*.ts" | grep -i cors
```

### 13. Missing Rate Limiting

**Dangerous:**
```javascript
// No rate limiting on login or API endpoints
app.post('/login', (req, res) => {
  authenticate(req.body);
});

app.post('/api/reset-password', (req, res) => {
  sendResetEmail(req.body.email);
});
```

**Safe:**
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/login', loginLimiter, (req, res) => {
  authenticate(req.body);
});

// Global API limiter
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100
});
app.use('/api/', apiLimiter);
```

**Detection:**
```bash
grep -rn "rate.limit\|rateLimit\|express-rate-limit\|express-slow-down" package.json
grep -rn "rateLimit\|rateLimiter\|slowDown" --include="*.js" --include="*.ts"
```

### 14. Cookie Security Flags Missing

**Dangerous:**
```javascript
app.use(session({
  secret: 'keyboard cat',
  cookie: {}  // No security flags
}));

res.cookie('session', token); // No flags
```

**Safe:**
```javascript
app.use(session({
  secret: process.env.SESSION_SECRET,
  name: '__Host-session', // Cookie prefix for extra security
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 3600000, // 1 hour
    domain: 'myapp.com',
    path: '/'
  },
  resave: false,
  saveUninitialized: false
}));
```

**Detection:**
```bash
grep -rn "session({" --include="*.js" --include="*.ts" -A 10
grep -rn "res\.cookie(" --include="*.js" --include="*.ts"
grep -rn "secure:\|httpOnly:\|sameSite:" --include="*.js" --include="*.ts"
```

---

## Framework Extension Security

### 15. Passport.js Misconfiguration

**Dangerous:**
```javascript
// Not checking authentication result
passport.authenticate('local')(req, res, next);

// Missing failure handling
app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard'
  // No failureRedirect or failureMessage
}));

// Session fixation - not regenerating session
app.post('/login', passport.authenticate('local'), (req, res) => {
  res.redirect('/dashboard'); // Same session ID before and after login
});
```

**Safe:**
```javascript
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ message: info.message });
    // Regenerate session to prevent fixation
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.logIn(user, (err) => {
        if (err) return next(err);
        res.redirect('/dashboard');
      });
    });
  })(req, res, next);
});
```

**Detection:**
```bash
grep -rn "passport\.authenticate" --include="*.js" --include="*.ts"
grep -rn "session\.regenerate" --include="*.js" --include="*.ts"
grep -rn "passport\.use\|new.*Strategy" --include="*.js" --include="*.ts"
```

### 16. Multer File Upload Issues

**Dangerous:**
```javascript
const multer = require('multer');

// No limits, any file type
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.any(), (req, res) => {
  res.send('Uploaded');
});

// Storing with original filename (path traversal risk)
const storage = multer.diskStorage({
  filename: (req, file, cb) => {
    cb(null, file.originalname); // Dangerous
  }
});
```

**Safe:**
```javascript
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const ALLOWED_MIMES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];

const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, crypto.randomUUID() + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIMES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  }
});

app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ filename: req.file.filename });
});
```

**Detection:**
```bash
grep -rn "multer(" --include="*.js" --include="*.ts"
grep -rn "upload\.any\|upload\.fields\|upload\.single\|upload\.array" --include="*.js" --include="*.ts"
grep -rn "fileFilter\|limits:" --include="*.js" --include="*.ts" | grep -i multer
grep -rn "originalname" --include="*.js" --include="*.ts"
```

---

## Detection Commands

```bash
# Full Express security scan
echo "=== Code Execution ==="
grep -rn "eval(\|new Function(\|vm\.run" --include="*.js" --include="*.ts"

echo "=== Command Injection ==="
grep -rn "exec(\|execSync\|spawn(\|shell:.*true" --include="*.js" --include="*.ts"

echo "=== SQL Injection ==="
grep -rn "query(.*\`\|query(.*+\|query(.*concat" --include="*.js" --include="*.ts"

echo "=== NoSQL Injection ==="
grep -rn "\\$where\|\\$regex\|\\$ne\|\\$gt" --include="*.js" --include="*.ts"
grep -rn "findOne(.*req\.\|find(.*req\." --include="*.js" --include="*.ts"

echo "=== Prototype Pollution ==="
grep -rn "merge(\|assign(\|extend(\|__proto__" --include="*.js" --include="*.ts"

echo "=== SSRF ==="
grep -rn "axios\.\|node-fetch\|got(\|fetch(" --include="*.js" --include="*.ts" | grep "req\."

echo "=== Path Traversal ==="
grep -rn "sendFile(.*req\|readFile(.*req\|createReadStream(.*req" --include="*.js" --include="*.ts"

echo "=== XSS ==="
grep -rn "res\.send(.*\`.*\${\|innerHTML\|document\.write" --include="*.js" --include="*.ts" --include="*.ejs"

echo "=== Security Headers ==="
grep -rn "helmet" package.json

echo "=== Debug ==="
grep -rn "\-\-inspect" package.json Dockerfile Procfile

echo "=== JWT ==="
grep -rn "jwt\.sign\|jwt\.verify" --include="*.js" --include="*.ts"
```

---

## Audit Checklist

- [ ] No `eval()`, `new Function()`, or `vm.runInContext()` with user input
- [ ] No `exec()` or `execSync()` with `shell: true` and user input
- [ ] All SQL queries use parameterized statements (no string concatenation)
- [ ] MongoDB queries sanitize input (no `$where`, no object injection)
- [ ] Prototype pollution mitigated in merge/assign operations
- [ ] `--inspect` flag not present in production configs
- [ ] `helmet.js` configured and active
- [ ] CORS origins explicitly listed (no wildcard with credentials)
- [ ] Rate limiting on authentication and sensitive endpoints
- [ ] Cookie flags: `secure`, `httpOnly`, `sameSite` set
- [ ] File uploads validate type, size, and use random filenames
- [ ] Path traversal prevented (resolved paths checked against base directory)
- [ ] SSRF mitigated (URL validation, private IP blocking)
- [ ] JWT tokens have expiry, fixed algorithm, strong secret
- [ ] Passport.js properly handles failures and regenerates sessions
- [ ] Express trust proxy configured correctly if behind reverse proxy
- [ ] Error handler does not leak stack traces in production (`NODE_ENV=production`)
