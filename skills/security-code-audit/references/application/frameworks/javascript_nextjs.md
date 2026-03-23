# Next.js/React Framework - Security Vulnerability Reference

## Identification Features

```bash
# Detect Next.js usage
grep -r "\"next\"" package.json
grep -r "next/\|from 'next\|from \"next" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
ls -la next.config.js next.config.mjs next.config.ts 2>/dev/null
ls -la pages/ app/ src/pages/ src/app/ 2>/dev/null
grep -r "getServerSideProps\|getStaticProps\|getInitialProps" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
```

Common file patterns: `next.config.js`, `pages/` or `app/` directory, `pages/api/`, `middleware.ts`, `.env.local`.

---

## Critical Vulnerabilities

### 1. Server-Side Code Leaked to Client Bundles

API keys, database credentials, or secrets included in client-side code through improper imports or `NEXT_PUBLIC_` prefix misuse.

**Dangerous:**
```javascript
// pages/index.js - importing server module in client component
import { db } from '../lib/database'; // DB credentials bundled to client

export default function Home() {
  // This file is a page component - code here ends up in the client bundle
  const apiKey = process.env.STRIPE_SECRET_KEY; // undefined on client, but may leak in build
  return <div>Home</div>;
}

// lib/api.js - mixed server/client code
const API_SECRET = 'sk_live_abc123'; // Hardcoded secret in shared module
export const fetchData = () => fetch('/api/data', {
  headers: { 'X-API-Key': API_SECRET }
});

// Accidentally exposing via NEXT_PUBLIC_
// .env.local
// NEXT_PUBLIC_DB_PASSWORD=supersecret  // Exposed to all clients
// NEXT_PUBLIC_API_SECRET=sk_live_abc123
```

**Safe:**
```javascript
// Server-only code stays in API routes or getServerSideProps
// pages/api/data.js
import { db } from '../../lib/database'; // Only runs server-side

export default async function handler(req, res) {
  const data = await db.query('SELECT * FROM items');
  res.json(data);
}

// pages/index.js - client component only uses public APIs
export default function Home({ data }) {
  return <div>{data.title}</div>;
}

export async function getServerSideProps() {
  // Server-only: safe to use secrets here
  const res = await fetch('https://api.example.com/data', {
    headers: { 'Authorization': `Bearer ${process.env.API_SECRET}` }
  });
  const data = await res.json();
  return { props: { data } }; // Only serialized data sent to client
}

// .env.local - only prefix NEXT_PUBLIC_ for truly public values
// NEXT_PUBLIC_APP_NAME=MyApp          // OK: public info
// STRIPE_SECRET_KEY=sk_live_abc123    // No prefix: server-only
// DATABASE_URL=postgres://...         // No prefix: server-only
```

**Detection:**
```bash
grep -rn "NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*KEY\|NEXT_PUBLIC_.*PASSWORD\|NEXT_PUBLIC_.*TOKEN" .env .env.local .env.production
grep -rn "NEXT_PUBLIC_" .env .env.local .env.production
# Check for server-only imports in page/component files
grep -rn "import.*database\|import.*prisma\|import.*mongoose\|require.*database" --include="*.jsx" --include="*.tsx" | grep -v "pages/api\|app/api\|getServerSideProps\|getStaticProps"
grep -rn "process\.env\." --include="*.jsx" --include="*.tsx" | grep -v "NEXT_PUBLIC_\|getServerSideProps\|getStaticProps"
```

### 2. getServerSideProps / Server Components with Unsanitized Data

Data from getServerSideProps or Server Components passed directly to client without sanitization can enable XSS when rendered.

**Dangerous:**
```javascript
// pages/profile/[id].js
export async function getServerSideProps({ params }) {
  const user = await db.query(`SELECT * FROM users WHERE id = ${params.id}`);
  // SQL injection in server-side data fetching
  return { props: { user } };
}

// app/page.tsx (Server Component) - passing raw HTML to client
export default async function Page({ searchParams }) {
  const results = await db.query('SELECT * FROM posts WHERE title LIKE ?', [`%${searchParams.q}%`]);
  return (
    <div>
      <h1>Results for: {searchParams.q}</h1>
      {/* If searchParams.q contains script tags and is rendered as HTML elsewhere */}
      {results.map(r => (
        <div key={r.id} dangerouslySetInnerHTML={{ __html: r.content }} />
      ))}
    </div>
  );
}
```

**Safe:**
```javascript
// pages/profile/[id].js
export async function getServerSideProps({ params }) {
  const id = parseInt(params.id, 10);
  if (isNaN(id)) return { notFound: true };
  const user = await db.query('SELECT * FROM users WHERE id = ?', [id]);
  if (!user) return { notFound: true };
  // Return only needed fields
  return {
    props: {
      user: { name: user.name, bio: user.bio }
    }
  };
}

// Sanitize any HTML content before rendering
import DOMPurify from 'isomorphic-dompurify';

export default function Post({ content }) {
  const clean = DOMPurify.sanitize(content);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

**Detection:**
```bash
grep -rn "getServerSideProps\|getStaticProps\|getInitialProps" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "params\.\|query\.\|searchParams\." --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" | grep -i "sql\|query\|exec\|db\."
grep -rn "dangerouslySetInnerHTML" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
```

### 3. API Route Injection

Next.js API routes are full Node.js handlers; they are susceptible to all server-side injection types.

**Dangerous:**
```javascript
// pages/api/users.js
import { exec } from 'child_process';

export default function handler(req, res) {
  const { cmd } = req.query;
  exec(cmd, (error, stdout) => { // Command injection
    res.status(200).json({ output: stdout });
  });
}

// pages/api/search.js
export default async function handler(req, res) {
  const { q } = req.query;
  const results = await db.query(`SELECT * FROM items WHERE name = '${q}'`); // SQL injection
  res.json(results);
}

// pages/api/eval.js
export default function handler(req, res) {
  const result = eval(req.body.expression); // RCE
  res.json({ result });
}
```

**Safe:**
```javascript
// pages/api/search.js
import { z } from 'zod';

const searchSchema = z.object({
  q: z.string().min(1).max(100),
  page: z.coerce.number().int().positive().default(1)
});

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  const parsed = searchSchema.safeParse(req.query);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues });
  }
  const { q, page } = parsed.data;
  const results = await db.query(
    'SELECT * FROM items WHERE name LIKE ? LIMIT 20 OFFSET ?',
    [`%${q}%`, (page - 1) * 20]
  );
  res.json(results);
}
```

**Detection:**
```bash
grep -rn "exec(\|execSync(\|eval(\|Function(" --include="*.js" --include="*.ts" | grep "pages/api\|app/api"
grep -rn "req\.query\|req\.body\|req\.params" --include="*.js" --include="*.ts" | grep "pages/api\|app/api"
# Check for missing input validation in API routes
find . -path "*/pages/api/*" -o -path "*/app/api/*" | head -20
```

---

## High Vulnerabilities

### 4. XSS via dangerouslySetInnerHTML

React escapes content by default, but `dangerouslySetInnerHTML` bypasses this.

**Dangerous:**
```jsx
// Rendering user input as HTML
function Comment({ text }) {
  return <div dangerouslySetInnerHTML={{ __html: text }} />;
}

// Rendering markdown without sanitization
import { marked } from 'marked';
function MarkdownPreview({ content }) {
  return <div dangerouslySetInnerHTML={{ __html: marked(content) }} />;
}

// Rendering HTML from API response without sanitization
function Post({ htmlContent }) {
  return <article dangerouslySetInnerHTML={{ __html: htmlContent }} />;
}
```

**Safe:**
```jsx
// Use DOMPurify to sanitize HTML
import DOMPurify from 'dompurify';

function Comment({ text }) {
  const clean = DOMPurify.sanitize(text, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href']
  });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// For markdown, sanitize the output
import { marked } from 'marked';
import DOMPurify from 'dompurify';

function MarkdownPreview({ content }) {
  const html = marked(content);
  const clean = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// Better: use a React markdown component that does not use dangerouslySetInnerHTML
import ReactMarkdown from 'react-markdown';
function MarkdownPreview({ content }) {
  return <ReactMarkdown>{content}</ReactMarkdown>;
}
```

**Detection:**
```bash
grep -rn "dangerouslySetInnerHTML" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "DOMPurify\|dompurify\|sanitize-html\|isomorphic-dompurify" package.json
grep -rn "DOMPurify\|sanitize(" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
```

### 5. SSRF in API Routes

**Dangerous:**
```javascript
// pages/api/proxy.js
export default async function handler(req, res) {
  const { url } = req.query;
  // Attacker: /api/proxy?url=http://169.254.169.254/latest/meta-data/
  const response = await fetch(url);
  const data = await response.text();
  res.send(data);
}

// pages/api/webhook.js
export default async function handler(req, res) {
  const { callback_url } = req.body;
  await fetch(callback_url, {
    method: 'POST',
    body: JSON.stringify({ status: 'complete' })
  });
  res.json({ ok: true });
}
```

**Safe:**
```javascript
// pages/api/proxy.js
import { URL } from 'url';

const ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com'];

function isAllowedUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    if (!ALLOWED_DOMAINS.includes(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

export default async function handler(req, res) {
  const { url } = req.query;
  if (!isAllowedUrl(url)) {
    return res.status(403).json({ error: 'URL not allowed' });
  }
  const response = await fetch(url, { redirect: 'error' });
  const data = await response.text();
  res.send(data);
}
```

**Detection:**
```bash
grep -rn "fetch(\|axios\.\|got(\|request(" --include="*.js" --include="*.ts" | grep "pages/api\|app/api\|route\.ts\|route\.js" | grep "req\.\|query\.\|body\.\|params\."
```

### 6. SQL Injection in API Routes

**Dangerous:**
```javascript
// pages/api/user/[id].js
import { pool } from '../../../lib/db';

export default async function handler(req, res) {
  const { id } = req.query;
  const result = await pool.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(result.rows);
}

// With Prisma - raw query injection
import prisma from '../../../lib/prisma';

export default async function handler(req, res) {
  const { search } = req.query;
  const users = await prisma.$queryRawUnsafe(
    `SELECT * FROM users WHERE name LIKE '%${search}%'`
  );
  res.json(users);
}
```

**Safe:**
```javascript
// pages/api/user/[id].js
import { pool } from '../../../lib/db';

export default async function handler(req, res) {
  const { id } = req.query;
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  res.json(result.rows);
}

// With Prisma - use parameterized queries
import prisma from '../../../lib/prisma';

export default async function handler(req, res) {
  const { search } = req.query;
  // Use Prisma ORM
  const users = await prisma.user.findMany({
    where: { name: { contains: search } }
  });
  // Or parameterized raw query
  const users2 = await prisma.$queryRaw`
    SELECT * FROM users WHERE name LIKE ${'%' + search + '%'}
  `;
  res.json(users);
}
```

**Detection:**
```bash
grep -rn "query(.*\`\|query(.*+\|\$queryRawUnsafe\|\$executeRawUnsafe" --include="*.js" --include="*.ts" | grep "pages/api\|app/api\|route\.ts\|route\.js"
grep -rn "pool\.query\|connection\.query\|db\.query" --include="*.js" --include="*.ts" | grep "pages/api\|app/api"
```

### 7. Missing Authentication on API Routes

**Dangerous:**
```javascript
// pages/api/admin/users.js - no auth check
export default async function handler(req, res) {
  const users = await db.query('SELECT * FROM users');
  res.json(users); // Anyone can list all users
}

// pages/api/admin/delete-user.js - no auth check
export default async function handler(req, res) {
  await db.query('DELETE FROM users WHERE id = ?', [req.body.id]);
  res.json({ success: true }); // Anyone can delete users
}
```

**Safe:**
```javascript
// lib/auth.js - reusable auth middleware
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../pages/api/auth/[...nextauth]';

export async function requireAuth(req, res) {
  const session = await getServerSession(req, res, authOptions);
  if (!session) {
    res.status(401).json({ error: 'Unauthorized' });
    return null;
  }
  return session;
}

export async function requireAdmin(req, res) {
  const session = await requireAuth(req, res);
  if (!session) return null;
  if (session.user.role !== 'admin') {
    res.status(403).json({ error: 'Forbidden' });
    return null;
  }
  return session;
}

// pages/api/admin/users.js
import { requireAdmin } from '../../../lib/auth';

export default async function handler(req, res) {
  const session = await requireAdmin(req, res);
  if (!session) return;
  const users = await db.query('SELECT * FROM users');
  res.json(users);
}
```

**Detection:**
```bash
# Find API routes without auth checks
grep -rL "getSession\|getServerSession\|getToken\|auth(\|requireAuth\|isAuthenticated\|verify.*token\|jwt\.verify" pages/api/**/*.{js,ts} app/api/**/*.{js,ts} 2>/dev/null
grep -rn "export default\|export async" --include="*.js" --include="*.ts" | grep "pages/api\|app/api"
grep -rn "getSession\|getServerSession\|getToken\|NextAuth" --include="*.js" --include="*.ts" | grep "pages/api\|app/api"
```

---

## Medium Vulnerabilities

### 8. CORS Misconfiguration

**Dangerous:**
```javascript
// pages/api/data.js
export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.json({ data: 'sensitive' });
}

// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      },
    ];
  },
};
```

**Safe:**
```javascript
// lib/cors.js
const ALLOWED_ORIGINS = ['https://myapp.com', 'https://admin.myapp.com'];

export function cors(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  }
}

// Or use next-cors package
import Cors from 'nextjs-cors';

export default async function handler(req, res) {
  await Cors(req, res, {
    methods: ['GET', 'POST'],
    origin: ['https://myapp.com'],
    credentials: true,
  });
  res.json({ data: 'ok' });
}
```

**Detection:**
```bash
grep -rn "Access-Control-Allow-Origin.*\*" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "Access-Control-Allow-Credentials.*true" --include="*.js" --include="*.ts"
grep -rn "cors\|CORS" next.config.js next.config.mjs next.config.ts
```

### 9. Missing Content Security Policy (CSP) Headers

**Dangerous:**
```javascript
// next.config.js - no security headers
module.exports = {
  // No headers configured
};

// Or overly permissive CSP
// Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval';
```

**Safe:**
```javascript
// next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'nonce-{nonce}'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self' https://api.myapp.com",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; ')
  },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
};
```

**Detection:**
```bash
grep -rn "Content-Security-Policy\|X-Frame-Options\|Strict-Transport-Security" next.config.js next.config.mjs next.config.ts
grep -rn "headers()" next.config.js next.config.mjs next.config.ts
grep -rn "securityHeaders\|security-headers" --include="*.js" --include="*.ts"
```

### 10. Exposed Environment Variables via NEXT_PUBLIC_

**Dangerous:**
```bash
# .env.local
NEXT_PUBLIC_API_SECRET=sk_live_abc123def456
NEXT_PUBLIC_DATABASE_URL=postgres://user:password@host/db
NEXT_PUBLIC_ADMIN_PASSWORD=admin123
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_xyz
NEXT_PUBLIC_JWT_SECRET=mysupersecret
```

**Safe:**
```bash
# .env.local
# Public (safe to expose to browser):
NEXT_PUBLIC_APP_NAME=MyApp
NEXT_PUBLIC_API_URL=https://api.myapp.com
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_abc123

# Private (server-only):
API_SECRET=sk_live_abc123def456
DATABASE_URL=postgres://user:password@host/db
STRIPE_SECRET_KEY=sk_live_xyz
JWT_SECRET=a-long-random-secret-string
```

**Detection:**
```bash
grep -rn "NEXT_PUBLIC_" .env .env.local .env.production .env.development
grep -rn "NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*PASSWORD\|NEXT_PUBLIC_.*KEY\|NEXT_PUBLIC_.*TOKEN\|NEXT_PUBLIC_.*DATABASE\|NEXT_PUBLIC_.*PRIVATE" .env .env.local .env.production .env.development
# Check what NEXT_PUBLIC_ vars exist in the client bundle
grep -rn "process\.env\.NEXT_PUBLIC_" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
```

### 11. Open Redirect

**Dangerous:**
```javascript
// pages/api/redirect.js
export default function handler(req, res) {
  const { url } = req.query;
  res.redirect(url); // /api/redirect?url=https://evil.com
}

// In client-side code
import { useRouter } from 'next/router';

function LoginPage() {
  const router = useRouter();
  const { redirect } = router.query;

  const handleLogin = async () => {
    await login();
    router.push(redirect); // Open redirect
  };
}
```

**Safe:**
```javascript
// pages/api/redirect.js
export default function handler(req, res) {
  const { url } = req.query;
  const allowed = ['/dashboard', '/profile', '/settings'];
  // Only allow relative paths to known routes
  if (url && url.startsWith('/') && !url.startsWith('//') && allowed.some(p => url.startsWith(p))) {
    res.redirect(url);
  } else {
    res.redirect('/');
  }
}

// Client-side
function LoginPage() {
  const router = useRouter();
  const { redirect } = router.query;

  const handleLogin = async () => {
    await login();
    // Validate redirect is a relative path
    const target = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//')
      ? redirect
      : '/dashboard';
    router.push(target);
  };
}
```

**Detection:**
```bash
grep -rn "res\.redirect(.*req\.\|res\.redirect(.*query\|router\.push(.*query\|router\.replace(.*query" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
grep -rn "redirect\|return_to\|next=" --include="*.js" --include="*.ts" | grep "query\|searchParams\|URLSearchParams"
```

---

## Detection Commands

```bash
# Full Next.js security scan
echo "=== Leaked Secrets ==="
grep -rn "NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*KEY\|NEXT_PUBLIC_.*PASSWORD\|NEXT_PUBLIC_.*TOKEN" .env .env.local .env.production 2>/dev/null

echo "=== Server Code in Client ==="
grep -rn "import.*database\|import.*prisma\|require.*database" --include="*.jsx" --include="*.tsx" | grep -v "pages/api\|app/api\|getServerSideProps\|getStaticProps"

echo "=== dangerouslySetInnerHTML ==="
grep -rn "dangerouslySetInnerHTML" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"

echo "=== API Route Injection ==="
grep -rn "eval(\|exec(\|execSync(\|Function(" --include="*.js" --include="*.ts" | grep "pages/api\|app/api"

echo "=== SQL Injection ==="
grep -rn "query(.*\`\|\$queryRawUnsafe\|\$executeRawUnsafe" --include="*.js" --include="*.ts" | grep "pages/api\|app/api"

echo "=== SSRF ==="
grep -rn "fetch(.*req\.\|axios.*req\." --include="*.js" --include="*.ts" | grep "pages/api\|app/api"

echo "=== Missing Auth on API Routes ==="
grep -rL "getSession\|getServerSession\|getToken\|auth(\|requireAuth\|jwt\.verify" pages/api/**/*.{js,ts} app/api/**/*.{js,ts} 2>/dev/null

echo "=== CORS ==="
grep -rn "Access-Control-Allow-Origin.*\*" --include="*.js" --include="*.ts"

echo "=== Security Headers ==="
grep -rn "Content-Security-Policy\|X-Frame-Options\|Strict-Transport" next.config.js next.config.mjs next.config.ts 2>/dev/null

echo "=== Open Redirect ==="
grep -rn "res\.redirect(.*req\.\|router\.push(.*query" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx"
```

---

## Audit Checklist

- [ ] No secrets (API keys, DB credentials) prefixed with `NEXT_PUBLIC_`
- [ ] Server-only modules not imported in page components or client code
- [ ] `getServerSideProps`/`getStaticProps` use parameterized queries, no SQL injection
- [ ] `dangerouslySetInnerHTML` only used with DOMPurify-sanitized content
- [ ] No `eval()`, `exec()`, or `Function()` in API routes with user input
- [ ] All API routes validate input (use zod, joi, or similar)
- [ ] All API routes with sensitive data check authentication/authorization
- [ ] SQL queries in API routes use parameterized statements or ORM
- [ ] SSRF mitigated: API routes validate outbound URLs
- [ ] CORS headers specify explicit origins (no wildcard with credentials)
- [ ] CSP headers configured in `next.config.js`
- [ ] Security headers set: X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy
- [ ] Open redirects validated (only allow relative paths to known routes)
- [ ] `.env.local` not committed to version control
- [ ] API routes check HTTP method (`req.method`) and return 405 for unsupported methods
- [ ] Rate limiting applied to authentication and sensitive API endpoints
- [ ] `middleware.ts` used for route-level auth where appropriate
- [ ] No hardcoded secrets in source code (use environment variables)
