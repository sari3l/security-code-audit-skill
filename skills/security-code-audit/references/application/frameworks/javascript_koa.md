# Koa Security Reference

## Identification Features

```bash
grep -r "require.*koa\|from.*koa" --include="*.js" --include="*.ts"
grep -r "new Koa(" --include="*.js" --include="*.ts"
grep -r "ctx\.\|koa-router\|@koa/router" --include="*.js" --include="*.ts"
```

Common file patterns: `app.js`, `server.js`, `middleware/`, `routes/`, `ctx.state` auth helpers.

---

## High-Risk Framework Surfaces

### 1. Middleware Ordering

- auth middleware registered after routers
- error handling that leaks stack traces in production
- body parsing absent or inconsistent across routes, leading to type confusion

### 2. `ctx.state` Trust

- handlers assuming `ctx.state.user` is always present and valid
- role checks done ad hoc and inconsistently
- upstream middleware allowing request-controlled values into `ctx.state`

### 3. File and Path Helpers

- `ctx.attachment`, `fs.createReadStream`, or `send` wrappers using query parameters directly
- archive and upload routes reusing original filenames

### 4. Koa + Raw Node APIs

- shell execution via `child_process`
- SSRF through `fetch`, `axios`, `got`, or `request`
- template engines using unescaped helpers

---

## Dangerous Patterns

```javascript
router.get("/admin", async (ctx) => {
  if (!ctx.state.user) return;
  ctx.body = await db.query("SELECT * FROM users");
});

router.get("/download", async (ctx) => {
  const file = ctx.query.file;
  ctx.body = fs.createReadStream(`/uploads/${file}`);
});
```

---

## Detection Commands

```bash
grep -rn "app\.use\|router\.(get|post|put|delete|patch)" --include="*.js" --include="*.ts"
grep -rn "ctx\.state\|ctx\.user\|authorization" --include="*.js" --include="*.ts"
grep -rn "createReadStream\|sendFile\|attachment\|ctx\.query" --include="*.js" --include="*.ts"
grep -rn "exec(\|execSync\|spawn(\|axios\|fetch(\|got(" --include="*.js" --include="*.ts"
```

---

## Audit Questions

- Is auth middleware guaranteed to run before every protected route?
- Are file and download routes constrained to safe directories?
- Are SSRF and command-injection sinks hidden inside service helpers rather than controllers?
- Does centralized error handling leak more than intended in non-dev environments?
