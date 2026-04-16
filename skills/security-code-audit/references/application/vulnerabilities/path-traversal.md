# Path Traversal Vulnerabilities

Path traversal happens when attacker-controlled path input is interpreted as a different location than the developer intended, letting it escape the intended base directory, object prefix, or extraction destination.

This is not limited to `../` reads or any fixed character list:
- arbitrary file read
- arbitrary file write or overwrite
- archive extraction outside the intended directory
- absolute-path or UNC/device-path abuse
- symlink and normalization bypasses
- parser and canonicalization mismatches across proxy, framework, and filesystem layers

---

## Where It Appears

- download, export, file viewer, template load, and import endpoints
- archive extraction and unpack flows
- image, PDF, or document helpers opening local files by user-influenced path
- object storage key composition and filesystem path builders
- log viewers, backup restore paths, and admin file browsers

---

## High-Risk Patterns

- `../`, `..\\`, encoded separators, doubled dots, or mixed slash normalization
- semicolon or path-parameter style delimiters, suffix markers, or alternate separators that one layer strips and another still interprets
- absolute path input overriding the intended base directory
- `join` / `combine` helpers used without checking the resolved path stays under the base directory
- archive entry names or extracted symlinks escaping the destination
- decode-before-check, check-before-decode, or normalize-once-then-reparse behavior
- path prefix checks performed before normalization or symlink resolution
- reverse proxy, router, framework, filesystem, and object-store layers disagreeing on the same path
- trusting object keys, bucket prefixes, or export paths that users can shape

---

## Commonly Missed Cases

- path traversal hidden inside file upload replacement, export, or post-processing flows
- Windows device, UNC, or alternate separator behavior ignored in cross-platform code
- sanitizers that strip only the exact literal `../`
- one layer ignores `;`, encoded separators, dot segments, or suffix markers while a later layer treats them as meaningful path input
- download endpoints with weaker controls than upload endpoints
- absolute path handling in framework helpers that discard the intended base path
- validation on the raw path but access on a decoded, normalized, or recombined path

---

## Root-Cause Lens

Do not define traversal by a payload family alone.

Define it by the semantic failure:
- attacker input survives into a path-like value
- some layer decodes, normalizes, trims, rejoins, or canonicalizes that value
- the final interpreted location crosses the intended boundary

This means review should focus on:
- how proxies, routers, frameworks, storage helpers, and filesystems each parse the path
- whether checks happen on the same representation that the final file access uses
- whether multiple path syntaxes or delimiters are accepted across layers

Public POCs such as encoded dot segments or `..;`-style probes are useful only because they reveal these semantic differences.
The root cause is interpretation drift, not the literal string itself.

---

## Safe Patterns

- generate server-side storage names or map user identifiers to fixed paths
- normalize and resolve the final path before use
- check the resolved path remains under the intended base directory
- reject absolute paths, traversal segments, unsafe archive entries, and symlink escapes
- keep filesystem paths and object-storage keys separate from user-facing filenames

---

## Audit Questions

- Who chooses the path, filename, key, or extraction destination?
- Which layers parse this path before the final open, read, write, or extract call?
- Is the final resolved path checked after every decode and normalization step that matters?
- Can absolute paths, encoded separators, semicolon-style segments, alternate delimiters, or archive entries escape the intended base?
- Do proxy, router, framework, and filesystem layers disagree on what the same path means?
- Can traversal combine with overwrite, download, or post-processing to amplify impact?
- Does a small path bug become critical when chained with IDOR, command execution, or secret exposure?

---

## Grep Starting Points

```bash
rg -n "sendFile|send_file|FileResponse|StreamingResponse|ServeFile|res\\.download|readFile|open\\(|fopen\\(|Path\\.Combine|path\\.join|filepath\\.Join" .
rg -n "\\.filename|originalname|upload|download|export|extract|unzip|untar|archive|zip" .
rg -n "\\.\\./|\\.\\.\\\\|normalize\\(|realpath\\(|resolve\\(|Clean\\(|secure_filename" .
rg -n "proxy_pass|alias|root|rewrite|try_files|location\\s|X-Accel-Redirect|X-Sendfile" .
```

---

## Related References

- `references/application/exploits/path-traversal.md`
- `references/application/vulnerabilities/file-upload-download.md`
- `references/application/vulnerabilities/authorization.md`
- `references/application/vulnerabilities/command-injection.md`
