# Sensitive Information Hardcoding

Sensitive information hardcoding happens when secrets, credentials, internal topology, or privileged connection metadata are committed directly into source, config, tests, examples, scripts, or generated artifacts.

Not every literal is equally severe, but all of these deserve review because they can enable:
- direct account or infrastructure compromise
- lateral movement using internal addresses and service names
- credential reuse across environments
- easier exploitation of other findings through leaked topology or admin paths

---

## What To Enumerate First

1. source files, config files, `.env*`, CI workflows, deploy manifests, examples, and seed data
2. code paths building auth clients, SDKs, webhooks, database connections, or admin integrations
3. generated artifacts such as crash dumps, backups, exports, docker layers, and compiled config
4. tests and fixtures that may still contain real secrets or production-like endpoints

---

## High-Risk Secret Families

### Version Control And Developer Platform Tokens

- GitHub PATs and fine-grained tokens such as `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
- GitLab PATs such as `glpat-...`
- Bitbucket, Azure DevOps, and self-hosted Git credentials
- deploy keys, machine users, and CI bot credentials

### Cloud Credentials

- AWS access keys and secret keys, session tokens, IAM user creds, STS temp creds
- Alibaba Cloud / Aliyun access key ID and secret
- Tencent Cloud / QCloud `AKID...` style secrets
- GCP service-account JSON, `private_key`, OAuth client secrets
- Azure storage connection strings, client secrets, SAS tokens
- Huawei Cloud, OCI, and other cloud access keys and signing keys

### Application And Platform Secrets

- `SECRET_KEY`, JWT signing keys, session secrets, CSRF secrets
- webhook signing secrets, HMAC keys, OAuth client secrets
- SMTP, SMS, payment, analytics, monitoring, and queue credentials
- Kubernetes service account tokens, kubeconfigs, Docker registry auth, `.npmrc` auth tokens

### Usernames, Passwords, And Connection Metadata

- hardcoded admin or service usernames and passwords
- database URLs and DSNs with embedded credentials
- Redis, MongoDB, AMQP, Kafka, Elasticsearch, SMTP, LDAP connection strings
- default credentials left in examples, migration scripts, or install code

### Private Keys And Sensitive Files

- RSA, EC, OpenSSH, PGP, PKCS#8 private keys
- certificate passphrases, keystore passwords, signing keys
- mobile signing keys, APNs keys, Firebase admin keys, SSO key material

### Internal Network And Topology Data

- RFC1918 addresses, VPC CIDRs, loopback-only admin URLs, metadata endpoints
- internal hostnames, service discovery names, bastion hosts, broker addresses
- admin panels, debug ports, metrics endpoints, private object-storage buckets

Internal topology is often lower impact than active credentials, but it still reduces attacker uncertainty and can materially help chaining.

---

## Commonly Missed Cases

- `.env.example`, sample config, or fixture data containing real values
- commented-out secrets left in source after rotation
- temporary credentials in shell scripts, notebooks, or release tooling
- secrets baked into Docker layers, generated JS bundles, or mobile app constants
- internal IPs and admin URLs hardcoded in frontend code, desktop clients, or test helpers
- old API keys kept for backward compatibility after migration

---

## Dangerous Patterns

```python
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DB_URL = "postgres://app:SuperSecret123@10.0.12.5:5432/prod"
```

```javascript
const gitlabToken = "glpat-xxxxxxxxxxxxxxxxxxxx";
const slackToken = "xoxb-123456789012-123456789012-xxxxxxxxxxxxxxxxxxxxxxxx";
const internalApi = "http://10.0.1.15:8080/admin";
```

```yaml
env:
  TENCENT_SECRET_ID: AKIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  TENCENT_SECRET_KEY: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  ALIYUN_ACCESS_KEY_ID: LTAI5txxxxxxxxxxxxxxx
```

```env
USERNAME=admin
PASSWORD=Welcome123!
JWT_SECRET=dev-secret-still-used
```

---

## Safe Patterns

- load secrets from a secret manager, injected environment, or runtime-only mount
- rotate and revoke any credential found in repo history, not just the current tree
- replace internal IP literals with environment-specific discovery or config indirection
- keep examples and fixtures obviously fake and non-routable
- store connection details without embedded credentials whenever the platform allows it

---

## Audit Questions

- Is the value still active, reachable, or valid in any environment?
- Does the hardcoded literal grant direct access, or does it reveal useful internal topology?
- Is the same secret reused across dev, staging, and production?
- Does the value also exist in git history, container layers, build logs, or generated assets?
- If rotated, was every downstream consumer updated and old access revoked?

---

## Grep Starting Points

```bash
grep -rnE 'gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9\\-_]{20,}' .
grep -rnE 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AKID[0-9A-Za-z]{16,}|LTAI[0-9A-Za-z]{12,}' .
grep -rnE 'AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_STORAGE_CONNECTION_STRING|GOOGLE_APPLICATION_CREDENTIALS|private_key' .
grep -rnE 'SECRET_KEY|JWT_SECRET|API_KEY|ACCESS_KEY|SECRET_ID|SECRET_KEY|TOKEN|WEBHOOK_SECRET' .
grep -rnE 'postgres(ql)?://[^[:space:]]+|mysql://[^[:space:]]+|mongodb(\\+srv)?://[^[:space:]]+|redis://[^[:space:]]+|amqps?://[^[:space:]]+' .
grep -rnE 'username\\s*=\\s*[\"'\"'\"'][^\"'\"'\"']+[\"'\"'\"']|password\\s*=\\s*[\"'\"'\"'][^\"'\"'\"']+[\"'\"'\"']' .
grep -rnE '-----BEGIN (RSA|EC|OPENSSH|PGP|DSA)? ?PRIVATE KEY-----|BEGIN OPENSSH PRIVATE KEY' .
grep -rnE '\\b10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\b|\\b192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}\\b|\\b172\\.(1[6-9]|2[0-9]|3[0-1])\\.[0-9]{1,3}\\.[0-9]{1,3}\\b|169\\.254\\.169\\.254' .
```

---

## Related References

- `references/application/vulnerabilities/data-exposure.md`
- `references/application/vulnerabilities/configuration-files.md`
- `references/application/languages/index.md`
