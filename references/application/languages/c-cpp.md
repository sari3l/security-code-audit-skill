# C / C++ Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers native services, CGI/FastCGI, embedded agents, RPC servers, and security-sensitive systems code.

---

## Language-Specific Hotspots

- Memory corruption primitives: overflows, use-after-free, double-free, integer overflow
- Dangerous process and format-string APIs: `system`, `popen`, `exec*`, `printf(user_input)`
- Privilege-boundary mistakes in setuid tools, service daemons, and file handling
- TLS, randomness, and build hardening gaps that turn bugs into reliable exploitation

---

## C1: Injection

### Key Questions
- Can user input reach `system`, `popen`, `execl`, `execvp`, or shell-command strings?
- Is user data ever used as a format string in `printf`, `syslog`, `fprintf`, or `snprintf`?
- Are embedded SQL APIs (`sqlite3_exec`, `mysql_query`, ODBC) fed concatenated strings?
- Are library or plugin paths user-controlled in `dlopen` / `LoadLibrary`?

### Dangerous Patterns

```c
system(user_input);
printf(user_input);

char sql[512];
snprintf(sql, sizeof(sql), "SELECT * FROM users WHERE id = %s", user_id);
sqlite3_exec(db, sql, NULL, NULL, NULL);

dlopen(user_path, RTLD_NOW);
```

### Safe Alternatives

```c
printf("%s", user_input);

sqlite3_stmt *stmt = NULL;
sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, NULL);
sqlite3_bind_text(stmt, 1, user_id, -1, SQLITE_TRANSIENT);

execl("/bin/ping", "ping", "-c", "1", validated_host, NULL);
```

### Grep Detection Patterns

```bash
grep -rn 'system\\(|popen\\(|execl\\(|execv\\(|execvp\\(|CreateProcess' --include="*.c" --include="*.cc" --include="*.cpp" --include="*.h"
grep -rn 'printf\\([^"]|fprintf\\([^,]*,[^"]|syslog\\([^,]*,[^"]|sprintf\\(' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'sqlite3_exec\\(|mysql_query\\(|PQexec\\(|SQLExecDirect' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'dlopen\\(|LoadLibrary' --include="*.c" --include="*.cc" --include="*.cpp"
```

---

## C2: Authentication

### Key Questions
- Are credentials hardcoded or compared with `strcmp` / `memcmp` in timing-leaky ways?
- Are tokens or session IDs generated with `rand()` / `srand(time(NULL))`?
- Do debug, maintenance, or factory-reset modes bypass auth?
- Are PAM, LDAP, or custom protocol errors interpreted safely?

### Detection

```bash
grep -rn 'strcmp\\(|memcmp\\(|strncmp\\(' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'rand\\(|srand\\(|random\\(' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'password|secret|backdoor|debug_auth|factory' --include="*.c" --include="*.cc" --include="*.cpp" --include="*.h"
```

---

## C3: Authorization

### Key Questions
- Are privilege checks separated cleanly from object access?
- Do setuid or service processes drop privileges immediately after sensitive setup?
- Are IPC objects, files, and sockets created with restrictive permissions?
- Is there any `access()` then `open()` or `stat()` then `use()` pattern?

### Detection

```bash
grep -rn 'setuid\\(|seteuid\\(|setgid\\(|cap_set' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'access\\(|stat\\(|lstat\\(' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'chmod\\(|umask\\(|open\\(.*0[0-7][0-7][0-7]' --include="*.c" --include="*.cc" --include="*.cpp"
```

---

## C4: Object Binding and Input Mapping

### Key Questions
- Does user-controlled structured input map directly into structs, flags, or config objects?
- Can bitmasks, enum values, or offset fields flip privileged behavior?
- Are protocol fields trusted before bounds, range, and semantic validation?
- Do deserializers or parsers write directly into security-sensitive members?

### Commonly Missed
- JSON keys bound into admin flags or file-system paths in custom parsers
- RPC structs where `role`, `uid`, or capability bits come from the client
- Signed/unsigned confusion allowing negative lengths or IDs to pass validation

### Detection

```bash
grep -rn 'memcpy\\(|memmove\\(|strncpy\\(|strcpy\\(|sscanf\\(' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'role|admin|uid|gid|perm|flags|capabilities|mask' --include="*.c" --include="*.cc" --include="*.cpp" --include="*.h"
```

---

## C5: Data Exposure

### Key Questions
- Do logs, debug endpoints, crash dumps, or traces expose secrets or memory contents?
- Can format-string bugs, uninitialized memory, or over-reads leak sensitive data?
- Are config files, core dumps, and temporary files readable by unintended users?
- Are TLS keys or credentials embedded in binaries or firmware images?

### Detection

```bash
grep -rn 'syslog\\(|fprintf\\(|printf\\(|backtrace\\(|core' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'BEGIN PRIVATE KEY|password|secret|token|apikey' --include="*.c" --include="*.cc" --include="*.cpp" --include="*.h"
```

---

## C6: Security Misconfiguration

### Key Questions
- Are assertions, debug handlers, or verbose traces left enabled in release builds?
- Are unsafe defaults used for file permissions, temporary files, or daemon users?
- Are network services listening broadly without TLS or authentication?
- Are runtime limits, seccomp, sandboxing, or namespaces absent where expected?

### Detection

```bash
grep -rn 'DEBUG|NDEBUG|assert\\(|TRACE|VERBOSE' --include="*.c" --include="*.cc" --include="*.cpp" --include="*.h"
grep -rn 'mktemp\\(|tmpnam\\(|tempnam\\(' --include="*.c" --include="*.cc" --include="*.cpp"
```

---

## C7: XSS and Output Injection

### Key Questions
- Does the native service render HTML, templates, or HTTP responses with unescaped input?
- Are CGI or FastCGI applications writing headers or HTML directly from request data?
- Are logs, CSV exports, or terminal UIs vulnerable to injection-style output issues?
- Can admin consoles or embedded web UIs echo attacker data into script contexts?

### Detection

```bash
grep -rn 'Content-Type: text/html|<html|<script|printf\\(.*REQUEST|printf\\(.*query' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'Set-Cookie|Location:|\\r\\n' --include="*.c" --include="*.cc" --include="*.cpp"
```

---

## C8: Dependencies

### Review Checklist
- Audit bundled libraries such as OpenSSL, libxml2, zlib, SQLite, libcurl, and image parsers.
- Identify vendored code copies, not just package-manager dependencies.
- Check compiler, libc, and TLS library versions against support windows.
- Flag libraries with known unsafe deserialization, parser, or decompression vulnerabilities.

### Detection

```bash
find . -name "CMakeLists.txt" -o -name "Makefile" -o -name "conanfile.*" -o -name "vcpkg.json"
grep -rn 'OpenSSL|libcurl|sqlite|zlib|libxml|protobuf|yaml' --include="*.cmake" --include="CMakeLists.txt" --include="Makefile"
```

---

## C9: Cryptography

### Key Questions
- Are keys, IVs, and salts generated from secure randomness?
- Are weak primitives like MD5, SHA1, DES, RC4, or ECB mode in use?
- Are secrets cleared from memory when practical?
- Is certificate validation enforced for TLS clients?

### Detection

```bash
grep -rn 'MD5|SHA1|DES_|RC4|EVP_des|EVP_rc4|ECB' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'rand\\(|srand\\(|arc4random|getrandom|RAND_bytes|/dev/urandom' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'SSL_CTX_set_verify|X509_VERIFY_PARAM|CURLOPT_SSL_VERIFYPEER|CURLOPT_SSL_VERIFYHOST' --include="*.c" --include="*.cc" --include="*.cpp"
```

---

## C10: SSRF and Network Reachability

### Key Questions
- Can user input choose URLs, hosts, ports, or schemes for outbound connections?
- Are redirects, local addresses, metadata IPs, and DNS rebinding handled?
- Are libcurl or raw socket clients restricted to intended destinations?
- Can proxy settings or environment variables override network boundaries?

### Detection

```bash
grep -rn 'curl_easy_setopt|CURLOPT_URL|getaddrinfo\\(|connect\\(|socket\\(' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'http://|https://|localhost|127\\.0\\.0\\.1|169\\.254\\.169\\.254' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'getenv\\("http_proxy"|getenv\\("HTTP_PROXY"' --include="*.c" --include="*.cc" --include="*.cpp"
```

---

## C11: Logging & Monitoring

### Key Questions
- Do logs contain secrets, raw memory, or user data without escaping?
- Can user input forge log records through format strings or embedded newlines?
- Are security events recorded separately from generic errors?
- Are crash handlers safe, or do they introduce reentrancy and signal-safety issues?

### Detection

```bash
grep -rn 'syslog\\(|openlog\\(|fprintf\\(|printf\\(' --include="*.c" --include="*.cc" --include="*.cpp"
grep -rn 'signal\\(|sigaction\\(' --include="*.c" --include="*.cc" --include="*.cpp"
```

---

## C12: Infrastructure & Build Hardening

### Key Questions
- Are stack canaries, PIE, RELRO, NX, FORTIFY, and warnings enabled?
- Do release builds strip debug-only code and symbols appropriately?
- Are containers or installers running native binaries with least privilege?
- Are sandboxing, seccomp, AppArmor, or systemd hardening options present where relevant?

### Detection

```bash
grep -rn 'stack-protector|FORTIFY|pie|relro|sanitize' --include="CMakeLists.txt" --include="Makefile" --include="*.cmake"
grep -rn 'USER root|--privileged|CAP_SYS_ADMIN' --include="Dockerfile" --include="*.service" --include="*.yml"
```
