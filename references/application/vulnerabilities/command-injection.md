# Command Injection Vulnerabilities

Command injection happens when untrusted input changes how the operating system or a called program interprets a process invocation.

This includes:
- shell metacharacter injection
- argument injection without an explicit shell
- option smuggling such as attacker-controlled `-o` or `--config`
- path and binary selection abuse
- environment or wrapper abuse around system utilities

---

## Where It Appears

- `system`, `exec`, `popen`, backticks, `subprocess(..., shell=True)`
- `Runtime.exec`, `Process.Start`, `child_process.exec`, `sh -c`
- wrappers around `tar`, `zip`, `ffmpeg`, `git`, `curl`, `wget`, `ping`, `nslookup`
- backup, import, image, document, and archive processing flows
- health-check or diagnostics endpoints exposed to admins or support roles

---

## High-Risk Patterns

- concatenating user input into a shell command string
- passing untrusted input as options to a program even without `shell=True`
- letting users influence executable paths, working directories, or config files
- assuming quoting is enough when the called program has dangerous flags
- calling helper scripts that reintroduce shell parsing later

---

## Commonly Missed Cases

- `execFile` or `subprocess.run([...])` can still be vulnerable to argument smuggling
- archive and media tools may interpret filenames beginning with `-` as options
- internal admin tooling often skips validation because it is "not public"
- hostnames, file paths, branch names, and image parameters frequently reach process helpers
- wrappers in shared utility modules hide the true sink from endpoint code

---

## Dangerous Patterns

```python
subprocess.run(f"tar -xf {archive}", shell=True)
os.system("ping -c 1 " + host)
```

```javascript
exec("git ls-remote " + repo)
spawn("tar", ["-xf", archivePath, userSuppliedName])
```

```java
Runtime.getRuntime().exec("ping " + host);
new ProcessBuilder("sh", "-c", script).start();
```

```php
system("convert " . $_GET["file"]);
```

```csharp
Process.Start("sh", "-c " + command);
```

---

## Safe Patterns

- avoid shell invocation entirely when a library API can do the job
- invoke binaries directly with fixed executable paths and fixed argument shapes
- validate each untrusted argument against a strict expected format
- terminate option parsing with `--` when the called program supports it
- isolate risky tooling behind narrow server-side allowlists

---

## Audit Questions

- Is a shell involved anywhere directly or indirectly?
- Can attacker input become a flag, config path, working directory, or binary name?
- Do filenames or hostnames beginning with `-` change program behavior?
- Are helper functions used across multiple routes or background jobs?
- Is there an out-of-band effect even when command output is not returned?

---

## Grep Starting Points

```bash
grep -rn 'system\\(|exec\\(|popen\\(|shell_exec\\(|passthru\\(' .
grep -rn 'shell=True|subprocess\\.run\\(|subprocess\\.Popen\\(|os\\.system\\(' .
grep -rn 'child_process|execFile|spawn\\(|ProcessBuilder|Runtime\\.getRuntime\\(\\)\\.exec|Process\\.Start' .
grep -rn 'tar |zip |unzip |ffmpeg|convert |curl |wget |git |ping |nslookup' .
grep -rn 'sh -c|bash -c|cmd /c|powershell -c' .
```

---

## Related References

- `references/application/exploits/command-injection.md`
- `references/application/vulnerabilities/injection.md`
- `references/application/frameworks/go_gin.md`
