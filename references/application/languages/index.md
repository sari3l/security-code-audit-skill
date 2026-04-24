# Language Search Patterns

Use this file as the fast entry point for language-specific grep starters and dangerous sink reminders.

It complements the deeper language files in this directory:
- `python.md`
- `javascript.md`
- `go.md`
- `java.md`
- `php.md`
- `ruby.md`
- `rust.md`
- `c-cpp.md`
- `swift.md`
- `kotlin.md`
- `dotnet.md`

For deep auditing, load this index first and then the specific language module that matches the project.

## Table of Contents
- [JavaScript / TypeScript](#javascript--typescript)
- [Python](#python)
- [Go](#go)
- [Java](#java)
- [.NET / C#](#net--c)
- [Ruby](#ruby)
- [PHP](#php)
- [Kotlin](#kotlin)
- [Rust](#rust)
- [Swift](#swift)
- [C / C++](#c--c)
- [Cross-Language Patterns](#cross-language-patterns)

## JavaScript / TypeScript

### Injection
```javascript
// Dangerous: command injection
exec(`git clone ${userInput}`);
// Dangerous: eval
eval(userProvidedCode);
// Dangerous: template literal in query
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
```

### XSS
```javascript
// Dangerous: innerHTML
element.innerHTML = userInput;
// Dangerous: document.write
document.write(data);
// Dangerous: dangerouslySetInnerHTML (React)
<div dangerouslySetInnerHTML={{__html: userContent}} />
```

### Prototype Pollution
```javascript
// Dangerous: recursive merge without key check
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key]; // __proto__ can be set
  }
}
```

### Search patterns
- `eval(`, `Function(`, `setTimeout(` with string args
- `innerHTML`, `outerHTML`, `document.write`
- `exec(`, `spawn(`, `execSync(`
- `dangerouslySetInnerHTML`
- `__proto__`, `constructor.prototype`
- `.query(` with template literals

## Python

### Injection
```python
# Dangerous: SQL injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# Dangerous: command injection
os.system(f"ping {host}")
subprocess.call(user_input, shell=True)
# Dangerous: eval/exec
eval(user_input)
# Dangerous: pickle deserialization
pickle.loads(untrusted_data)
```

### Path Traversal
```python
# Dangerous: no path validation
open(os.path.join(base_dir, user_filename))
```

### Search patterns
- `eval(`, `exec(`, `compile(`
- `os.system(`, `subprocess.call(`, `shell=True`
- `pickle.loads(`, `yaml.load(` (without SafeLoader)
- `.format(` and f-strings in SQL
- `os.path.join` with user input

## Go

### Injection
```go
// Dangerous: SQL injection
db.Query("SELECT * FROM users WHERE id = " + id)
// Dangerous: command injection
exec.Command("sh", "-c", userInput)
// Dangerous: template injection
template.HTML(userInput)
```

### Search patterns
- String concatenation in SQL queries
- `exec.Command` with user input
- `template.HTML(`, `template.JS(`, `template.URL(`
- `http.ListenAndServe(` without TLS
- Missing `defer rows.Close()`

## Java

### Injection
```java
// Dangerous: SQL injection
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
// Dangerous: command injection
Runtime.getRuntime().exec(userInput);
// Dangerous: XXE
DocumentBuilderFactory.newInstance(); // without disabling external entities
// Dangerous: deserialization
ObjectInputStream ois = new ObjectInputStream(untrustedStream);
ois.readObject();
```

### Search patterns
- `createStatement()` with string concat
- `Runtime.getRuntime().exec(`
- `ObjectInputStream`, `readObject()`
- `DocumentBuilderFactory` without XXE protection
- `@CrossOrigin("*")`

## .NET / C#

### Injection
```csharp
// Dangerous: raw SQL
db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}");
// Dangerous: command execution
Process.Start("cmd.exe", "/c " + input);
// Dangerous: JSON.NET type handling
var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
```

### Search patterns
- `FromSqlRaw`, `ExecuteSqlRaw`, `SqlCommand` with interpolation
- `Process.Start`, `ProcessStartInfo`
- `TypeNameHandling`, `BinaryFormatter`
- `AllowAnyOrigin`, `AllowCredentials`

## Ruby

### Search patterns
- `eval(`, `send(` with user input
- `system(`, backticks with interpolation
- `render inline:` with user input
- `find(params[:id])` without scoping
- `html_safe`, `raw(`

## PHP

### Search patterns
- `mysql_query(` with concatenation
- `eval(`, `system(`, `exec(`, `passthru(`
- `include(`, `require(` with user input (LFI/RFI)
- `unserialize(` with untrusted data
- `$_GET`, `$_POST` used directly without sanitization
- `extract(` with user data

## Kotlin

### Search patterns
- `JdbcTemplate`, `createQuery(`, `createNativeQuery(` with interpolation
- `Runtime.getRuntime().exec`, `ProcessBuilder`
- `@RequestBody` bound directly to entities
- `SharedPreferences` storing tokens or secrets
- `WebView`, `loadDataWithBaseURL`, `evaluateJavascript`

## Rust

### Search patterns (Rust is memory-safe but not immune)
- `unsafe` blocks — review each carefully
- `.unwrap()` in production code (panic risk)
- SQL queries built with `format!`
- `Command::new` with user input
- `std::mem::transmute`

## Swift

### Search patterns
- `NSPredicate(format:)` with interpolated input
- `Process`, `NSTask`, `launchPath`
- `WKWebView`, `loadHTMLString`, `evaluateJavaScript`
- `UserDefaults` storing tokens or credentials
- `NSAllowsArbitraryLoads` or broad ATS exceptions

## C / C++

### Search patterns
- `strcpy`, `strcat`, `sprintf`, `gets` (buffer overflow)
- `malloc` without size validation
- `free` followed by use (use-after-free)
- `printf(user_input)` (format string)
- Missing bounds checking on arrays

## Cross-Language Patterns

### Secrets in Code
```
password\s*=\s*["'][^"']+["']
api[_-]?key\s*=\s*["'][^"']+["']
secret\s*=\s*["'][^"']+["']
token\s*=\s*["'][^"']+["']
-----BEGIN (RSA |EC )?PRIVATE KEY-----
Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*
```

### Platform Tokens
```
gh[pousr]_[A-Za-z0-9_]{20,}
github_pat_[A-Za-z0-9_]{20,}
glpat-[A-Za-z0-9\-_]{20,}
xox[baprs]-[A-Za-z0-9-]{10,}
npm_[A-Za-z0-9]{20,}
```

### Cloud Credentials
```
AKIA[0-9A-Z]{16}
ASIA[0-9A-Z]{16}
AKID[0-9A-Za-z]{16,}
LTAI[0-9A-Za-z]{12,}
AWS_SECRET_ACCESS_KEY
AZURE_STORAGE_CONNECTION_STRING
GOOGLE_APPLICATION_CREDENTIALS
private_key
```

### Connection Strings And Embedded Credentials
```
postgres(ql)?://[^[:space:]]+
mysql://[^[:space:]]+
mongodb(\+srv)?://[^[:space:]]+
redis://[^[:space:]]+
amqps?://[^[:space:]]+
```

### Hardcoded IPs / URLs
```
https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
localhost:\d+
127\.0\.0\.1
0\.0\.0\.0
10\.\d{1,3}\.\d{1,3}\.\d{1,3}
192\.168\.\d{1,3}\.\d{1,3}
172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}
169\.254\.169\.254
```

### Debug / Development Artifacts
```
TODO.*security
FIXME.*auth
HACK
console\.log\(.*password
print\(.*secret
DEBUG\s*=\s*True
```
