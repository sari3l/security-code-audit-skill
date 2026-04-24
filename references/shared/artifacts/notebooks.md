# Notebook Security Review

Notebooks are high-risk mixed artifacts: code, markdown, outputs, credentials, and analyst habits all live in one file. Review the notebook source and its saved output, not just the executable cells.

---

## What To Enumerate First

1. Jupyter and other notebook files such as `.ipynb`
2. saved cell outputs, displayed tables, HTML, charts, and embedded media
3. imports, helper snippets, shell escapes, and subprocess use
4. environment loading, secret retrieval, DSNs, cloud SDK configuration, and local file paths
5. connections to internal databases, warehouses, notebooks services, and object storage

---

## High-Risk Patterns

- hardcoded API keys, tokens, cookies, DSNs, or passwords in cells or metadata
- saved outputs containing PII, query results, access tokens, or internal URLs
- shell commands, `%bash`, `!curl`, `!aws`, `!gcloud`, or other direct credential-bearing invocations
- notebooks used as operational runbooks with production endpoints and real credentials
- unchecked download or execution of remote artifacts inside notebook cells
- markdown and code cells mixed in ways that can steer operators or later automation
- internal network paths, bucket names, metadata endpoints, or cluster details exposed in examples or outputs

---

## Audit Questions

- Does the notebook contain live credentials or access tokens?
- Are sensitive query results or exported data preserved in output cells?
- Can shell escapes or helper scripts execute commands with inherited credentials?
- Are notebooks used as trusted operational guidance for production actions?
- Are internal systems, hosts, or storage layouts exposed even without explicit secrets?
- Is notebook output committed when the input cell was already cleaned up?

---

## Grep Starting Points

```bash
rg -n "\\.ipynb|jupyter|notebook|colab" .
rg -n "\"outputs\":|text/html|image/png|application/json|stdout|stderr" .
rg -n "token|api[_-]?key|secret|password|dsn|jdbc:|postgres://|mongodb://|aws_access_key_id|aws_secret_access_key" .
rg -n "!curl|!aws|!gcloud|!kubectl|!psql|%bash|subprocess|os\\.system|requests\\." .
rg -n "10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|metadata|internal|cluster|bucket|s3://" .
```

---

## Review Strategy

1. Review raw notebook JSON, not just rendered cells.
2. Check both source cells and saved outputs for secrets and data exposure.
3. Trace shell escapes, network calls, and notebook-to-production workflows.
4. Report notebook leaks separately from application-code findings when the risk is operational rather than runtime.

---

## Related References

- `references/application/vulnerabilities/sensitive-hardcoding.md`
- `references/application/vulnerabilities/data-exposure.md`
- `references/application/vulnerabilities/security-misconfiguration.md`
- `references/shared/artifacts/skill-files.md`
