# PHP Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers raw PHP, Laravel, Symfony, WordPress, and common Composer-based applications.

---

## Language-Specific Hotspots

- Superglobals flowing into sinks without normalization: `$_GET`, `$_POST`, `$_REQUEST`, `php://input`
- Dynamic include / autoload patterns: `include`, `require`, `spl_autoload_register`, template path composition
- Dangerous runtime features: `unserialize`, `eval`, `assert`, process execution, stream wrappers
- Framework-specific footguns: Eloquent mass assignment, Blade raw output, Twig `|raw`, WordPress capability gaps

---

## C1: Injection

### Key Questions
- Are SQL queries built with concatenation, interpolation, or raw query helpers?
- Can user input reach `system`, `exec`, `shell_exec`, backticks, or `proc_open`?
- Are file paths or template names user-controlled in `include` / `require`?
- Is `unserialize()` reachable from cookies, sessions, cache, or request bodies?

### Commonly Missed
- `orderByRaw`, `whereRaw`, `DB::statement`, `DB::select(DB::raw(...))`
- `extract($_REQUEST)` turning user keys into variables later reused in SQL or includes
- `preg_replace('/.../e', ...)` in legacy codebases
- PHP stream wrappers like `php://`, `data://`, `phar://`, `zip://`

### Dangerous Patterns

```php
// SQL injection
$sql = "SELECT * FROM users WHERE email = '" . $_GET['email'] . "'";
$rows = $pdo->query($sql);

// Command injection
system("ping -c 1 " . $_POST['host']);
echo shell_exec("tar -xf " . $archive);

// File inclusion
include "pages/" . $_GET['page'] . ".php";

// Object injection
$data = unserialize($_COOKIE['profile']);

// Laravel raw query helpers
User::whereRaw("email = '$email'")->first();
DB::statement("DELETE FROM sessions WHERE id = '$id'");
```

### Safe Alternatives

```php
// Parameterized SQL
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
$stmt->execute(['email' => $email]);

// Allowlist dynamic SQL fragments
$sort = in_array($request->get('sort'), ['name', 'created_at'], true)
    ? $request->get('sort')
    : 'created_at';
$users = User::orderBy($sort, 'desc')->get();

// Safe process execution: avoid shell, validate arguments
$host = filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
$cmd = ['/bin/ping', '-c', '1', $host];

// Safe template selection
$page = in_array($page, ['home', 'help', 'pricing'], true) ? $page : 'home';
include __DIR__ . "/pages/{$page}.php";
```

### Grep Detection Patterns

```bash
grep -rn '->query(.*\\.|mysqli_query(.*\\.|mysql_query(.*\\.|DB::raw\\(|whereRaw\\(|orderByRaw\\(' --include="*.php"
grep -rn 'system\\(|exec\\(|shell_exec\\(|passthru\\(|proc_open\\(|popen\\(|`' --include="*.php"
grep -rn 'include\\(|require\\(|include_once\\(|require_once\\(' --include="*.php"
grep -rn 'unserialize\\(|yaml_parse\\(|simplexml_load_' --include="*.php"
grep -rn 'extract\\($_(GET|POST|REQUEST|COOKIE)' --include="*.php"
```

---

## C2: Authentication

### Key Questions
- Are passwords hashed with `password_hash()` and verified with `password_verify()`?
- Is `session_regenerate_id(true)` called after login and privilege changes?
- Are JWT algorithms pinned and secrets sourced only from strong configuration?
- Do reset, OTP, and magic-link flows expire quickly and enforce rate limits?

### Commonly Missed
- `md5($password) == $storedHash` and loose comparisons like `==`
- Fallback secrets: `$_ENV['JWT_SECRET'] ?? 'dev-secret'`
- Remember-me tokens stored or compared in plaintext
- Separate legacy login routes without throttling

### Detection

```bash
grep -rn 'md5\\(|sha1\\(|hash\\("sha1"|hash\\("md5"' --include="*.php"
grep -rn 'password_hash\\(|password_verify\\(|session_regenerate_id\\(' --include="*.php"
grep -rn 'JWT_SECRET|secret.*fallback|firebase\\\\jwt|lcobucci' --include="*.php" --include=".env*"
grep -rn 'password_reset|resetPassword|forgotPassword|otp|magic' --include="*.php"
```

---

## C3: Authorization

### Key Questions
- Are resource lookups scoped to the current user or tenant, not just `id`?
- Do admin routes enforce role or policy checks server-side?
- Are WordPress AJAX handlers gated with `current_user_can()` and nonce validation?
- Do destructive actions have the same authorization depth as read actions?

### Commonly Missed
- Laravel route-model binding returning `Model::findOrFail($id)` without ownership checks
- `Auth::check()` used where `Gate::authorize()` or policies are required
- File downloads protected only by "must be logged in"
- Bulk actions authorizing the batch but not each object

### Detection

```bash
grep -rn 'find\\(|findOrFail\\(|firstOrFail\\(' --include="*.php"
grep -rn 'current_user_can\\(|check_ajax_referer\\(|wp_ajax_' --include="*.php"
grep -rn 'Gate::authorize\\(|\\$this->authorize\\(|can\\(' --include="*.php"
grep -rn 'Route::(delete|put|patch|post)' --include="*.php" -A 4
```

---

## C4: Mass Assignment

### Key Questions
- Are request payloads bound into entities or models without an allowlist?
- Does Eloquent use `fillable` correctly, or is `$guarded = []` present?
- Can nested input set privileged fields like `role`, `is_admin`, `balance`, `tenant_id`?
- Do profile-update or registration flows call `$request->all()` directly?

### Dangerous Patterns

```php
// Laravel
User::create($request->all());
$user->update($request->all());

class User extends Model {
    protected $guarded = [];
}

// Raw PHP hydrator
foreach ($_POST as $key => $value) {
    $user->$key = $value;
}
```

### Detection

```bash
grep -rn '\\$request->all\\(|fill\\(|forceFill\\(|create\\(\\$request|update\\(\\$request' --include="*.php"
grep -rn '\\$guarded\\s*=\\s*\\[\\]|\\$fillable' --include="*.php"
grep -rn 'role|is_admin|isAdmin|balance|tenant_id|credit_limit' --include="*.php"
```

---

## C5: Data Exposure

### Key Questions
- Are secrets stored in `.env`, config, or code and accidentally web-accessible?
- Do serializers expose hidden fields such as tokens, hashes, internal IDs, or tenant metadata?
- Are debug pages, stack traces, SQL errors, or `phpinfo()` reachable?
- Are uploaded files, exports, or backups accessible from the public web root?

### Detection

```bash
grep -rn 'phpinfo\\(|var_dump\\(|print_r\\(|APP_DEBUG|display_errors' --include="*.php" --include=".env*"
grep -rn 'hidden\\s*=|makeHidden\\(|visible\\s*=' --include="*.php"
grep -rn 'password|token|secret|api_key|private_key' --include="*.php" --include=".env*" --include="*.yaml"
find . -name ".env" -o -name "*.sql" -o -name "*.bak" -o -name "*.zip"
```

---

## C6: Security Misconfiguration

### Key Questions
- Is `display_errors` disabled and `APP_DEBUG=false` in production?
- Are dangerous wrappers or directives like `allow_url_include` enabled?
- Is CORS overly broad, or are cookies missing `Secure`, `HttpOnly`, `SameSite`?
- Are PHP-FPM, upload, session, and temporary directories configured safely?

### Detection

```bash
grep -rn 'APP_DEBUG|APP_ENV|display_errors|allow_url_include|allow_url_fopen|expose_php' --include=".env*" --include="*.ini" --include="*.php"
grep -rn 'setcookie\\(|Cookie::queue\\(|session_set_cookie_params' --include="*.php"
grep -rn 'Access-Control-Allow-Origin|cors|allowed_origins' --include="*.php" --include="*.yaml"
```

---

## C7: XSS

### Key Questions
- Are Blade, Twig, or raw PHP templates bypassing auto-escaping?
- Is user data embedded into JavaScript, CSS, URL, or HTML-attribute contexts safely?
- Are rich-text or markdown flows sanitized before being marked trusted?
- Can uploaded SVG or HTML files execute when served back?

### Dangerous Patterns

```php
// Blade raw output
{!! $comment->body !!}

// Twig raw filter
{{ content|raw }}

// Raw PHP echo into HTML/JS
echo "<script>var name = '$name'</script>";
```

### Detection

```bash
grep -rn '{!!|\\|raw\\b|htmlspecialchars\\(' --include="*.php" --include="*.blade.php" --include="*.twig"
grep -rn 'echo\\s+.*\\$_(GET|POST|REQUEST)|print\\s+.*\\$_(GET|POST|REQUEST)' --include="*.php"
grep -rn 'dangerously|loadHTML|innerHTML' --include="*.php" --include="*.js"
```

---

## C8: Dependencies

### Review Checklist
- Run `composer audit` and review abandoned packages.
- Check dev-only tools like PHPUnit, Laravel Telescope, and Debugbar are absent from production.
- Review WordPress plugins/themes and bundled vendor trees, not just top-level `composer.json`.
- Flag EOL PHP runtimes and frameworks as security debt even without a single code-level sink.

### Detection

```bash
composer audit
grep -rn '"require-dev"|phpunit|laravel/telescope|barryvdh/laravel-debugbar' composer.json composer.lock
grep -rn '"php":' composer.json
```

---

## C9: Cryptography

### Key Questions
- Are passwords, tokens, and HMACs using modern primitives?
- Are `openssl_encrypt` keys and IVs random, non-hardcoded, and mode-appropriate?
- Is `random_bytes()` used instead of `mt_rand()` / `rand()` for secrets?
- Are token comparisons constant-time with `hash_equals()`?

### Detection

```bash
grep -rn 'mt_rand\\(|rand\\(|uniqid\\(' --include="*.php"
grep -rn 'openssl_encrypt\\(|openssl_decrypt\\(|sodium_' --include="*.php"
grep -rn 'hash_equals\\(|password_hash\\(|password_verify\\(' --include="*.php"
grep -rn 'AES-128-ECB|AES-256-ECB|DES-' --include="*.php"
```

---

## C10: SSRF

### Key Questions
- Can user-controlled URLs reach `file_get_contents`, cURL, Guzzle, or `Http::get()`?
- Are redirects, DNS rebinding, IPv6 literals, decimal IPs, and cloud metadata blocked?
- Are webhook, import, preview, or image-fetch features validating destination hosts after resolution?
- Are dangerous schemes like `file://`, `dict://`, `gopher://`, or `ftp://` denied?

### Detection

```bash
grep -rn 'file_get_contents\\(|curl_init\\(|curl_setopt\\(|Http::(get|post|withOptions)|GuzzleHttp|Client\\(' --include="*.php"
grep -rn 'redirect|follow_redirects|CURLOPT_FOLLOWLOCATION|allow_redirects' --include="*.php"
grep -rn '169\\.254\\.169\\.254|metadata\\.google\\.internal|localhost|127\\.0\\.0\\.1' --include="*.php"
```

---

## C11: Logging & Monitoring

### Key Questions
- Are secrets, tokens, cookies, or request bodies logged?
- Can attackers forge log lines via unescaped newlines or structured-log field injection?
- Are auth failures, permission denials, and admin actions audited distinctly?
- Are exceptions routed to centralized monitoring without leaking sensitive context?

### Detection

```bash
grep -rn 'Log::|logger\\(|error_log\\(|Monolog' --include="*.php"
grep -rn 'Authorization|password|token|secret|cookie|set-cookie' --include="*.php"
grep -rn '\\\\n|PHP_EOL' --include="*.php"
```

---

## C12: Infrastructure & Deployment

### Key Questions
- Is PHP running as a non-privileged user with strict file permissions?
- Are upload directories non-executable and separated from the application root?
- Are session and cache backends protected from direct access?
- Do containers, images, or build pipelines leak secrets or enable debug tooling in production?

### Detection

```bash
find . -name "Dockerfile" -o -name "docker-compose.yml" -o -name "*.conf" -o -name "nginx*.conf"
grep -rn 'USER root|chmod 777|COPY \\.env|artisan serve|xdebug|phpinfo' --include="Dockerfile" --include="*.yml" --include="*.conf"
grep -rn 'session.save_path|upload_tmp_dir|open_basedir' --include="*.ini" --include="*.conf"
```
