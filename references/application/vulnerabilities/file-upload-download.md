# File Upload and Download Security

File handling bugs are not only about simple path traversal. Real review must cover upload, replace, delete, download, export, object storage, archive extraction, filename handling, quotas, and post-processing.

Typical impact includes:
- arbitrary file read or write
- cross-tenant overwrite or replacement
- stored XSS through SVG or HTML
- denial of service through oversized or compressed inputs
- public or replayable file access
- parser, archive, or media-processing exploitation

---

## What To Enumerate First

1. upload, import, replace, avatar, document, media, and archive endpoints
2. download, export, attachment, preview, and signed-URL issuance endpoints
3. storage backends: local disk, temp dirs, object storage, CDN, shared volumes
4. validators: extension, MIME, content sniffing, size, file count, aggregate quota
5. post-processing: image resize, OCR, AV scan, unzip, transcode, thumbnailing, metadata extraction
6. authorization points for upload replace, delete, download, export, and object-key selection

---

## High-Risk Patterns

- original filename used directly in filesystem paths, object keys, or response headers
- user-controlled object key, storage prefix, bucket path, export path, or archive extract destination
- path traversal in filenames via `../`, `..\\`, absolute paths, mixed separators, or encoded segments
- control characters, newlines, RTL characters, or header-breaking content in filenames
- filenames beginning with `-` that change downstream command behavior
- duplicate or same-name files overwriting an earlier validated file or another user's file
- replace endpoints that authorize the record but not the underlying stored object
- presigned upload or download URLs not bound tightly to user, object, size, or content type
- MIME or extension checks without content validation
- SVG, HTML, PDF, archive, office, or media files accepted without considering active content or parser risk
- missing max file size, count, aggregate quota, or multipart part limits
- decompression bombs, nested archives, or oversized image/media payloads
- scan-then-move or validate-then-publish races
- upload directories writable and executable, or directly served from a public web root
- temporary, quarantine, and published storage sharing the same namespace or path
- `Content-Disposition` built from untrusted filename without sanitization

---

## Commonly Missed Cases

- multi-file upload where two files share the same name and the later one overwrites the earlier validated one
- filename normalization differences between application code, filesystem, object storage, and CDN
- proxy, framework, archive, and storage layers disagreeing on separators, suffix markers, or decoded path segments
- mobile or API uploads bypassing web-form limits
- download endpoints with stronger checks in HTML pages than in raw API routes
- signed URLs that expire slowly, can be replayed, or can be reused across tenants
- archive extraction or import jobs writing outside the intended directory
- validators only enforced in frontend code or API gateway policy
- object storage ACLs or bucket policies exposing files even when app routes are protected

---

## Safe Patterns

- generate server-side random storage names or immutable object keys
- keep original filename only as sanitized metadata, not as the storage path
- enforce extension, MIME, and content-level validation where practical
- enforce max file size, max file count, and aggregate per-request or per-user quotas
- segregate temp, quarantine, and published storage
- scan or transform untrusted files before public serving when the file type is high risk
- validate resolved paths remain under the intended base directory
- bind replace, delete, download, export, and signed URL issuance to the correct owner or tenant
- use unique names or versioned keys to prevent overwrite races

---

## Audit Questions

- Who chooses the stored filename or object key: the client or the server?
- Do proxy, framework, filesystem, CDN, or object-store layers interpret the same filename or key differently?
- Can one user replace, overwrite, or download another user's file by reusing IDs or names?
- Are upload size, file count, and aggregate quotas enforced server-side?
- Are dangerous formats such as SVG, HTML, or archives handled with extra controls?
- Does archive extraction sanitize entry names and symlinks?
- Are download and export links guessable, replayable, or reusable after privilege changes?
- Do AV scan, thumbnail, OCR, or transcode jobs run before or after a file becomes accessible?
- Can errors, responses, or headers leak internal storage paths?

---

## Grep Starting Points

```bash
rg -n "upload|multipart|UploadFile|request\\.FILES|IFormFile|MultipartFile|multer|FormFile|file\\.save|save\\(|putObject|s3|blob|attachment|download|sendFile|FileResponse|StreamingResponse|Content-Disposition" .
rg -n "filename|originalname|getOriginalFilename|UploadFile\\.filename|secure_filename|Path\\.GetRandomFileName|uuid|randomUUID|object key|storage key|bucket" .
rg -n "MAX_CONTENT_LENGTH|maxFileSize|upload_max_filesize|client_max_body_size|maxRequestBodySize|MultipartBodyLengthLimit|sizeLimit|content_length|quota|file count" .
rg -n "zip|tar|extract|unzip|untar|archive|Zip Slip|symlink" .
rg -n "signed url|presign|pre-signed|temporaryUrl|generatePresigned|SAS|attachment token|download token" .
```

---

## Review Strategy

1. Start from upload, replace, export, and download routes.
2. Trace how the app derives the storage name, key, or path.
3. Check validation order: authz, type, size, scan, move, publish.
4. Check overwrite behavior for same-name and cross-tenant collisions.
5. Check download and export ownership enforcement separately from upload authz.
6. Cross-reference with `path-traversal`, `idor`, `xss`, and `command-injection` style impacts when post-processing or file reads are involved.

---

## Related References

- `references/application/vulnerabilities/path-traversal.md`
- `references/application/exploits/path-traversal.md`
- `references/application/exploits/idor.md`
- `references/application/vulnerabilities/authorization.md`
- `references/application/vulnerabilities/xss.md`
- `references/application/vulnerabilities/command-injection.md`
