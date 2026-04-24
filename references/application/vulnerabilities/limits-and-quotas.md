# Limits and Quotas Abuse

Use this file when users, tenants, plans, or workflows rely on counters, quotas, caps, rate limits, free-tier boundaries, or aggregate resource limits.

---

## High-Risk Surfaces

- per-user, per-tenant, or per-plan quotas
- free-tier or trial usage accounting
- upload size, file count, aggregate storage, or batch size limits
- coupon, invite, or redemption counts
- rate limits enforced only per request or only in the client

---

## Audit Questions

- Is the limit enforced on the real server-side source of truth?
- Is it per request, or truly aggregate across users, tenants, devices, or time windows?
- Can alternate identifiers, versions, or content types bypass the same cap?
- Can a small counting flaw combine with pricing, replay, or authz issues to create material abuse?

---

## Grep Starting Points

```bash
rg -n "quota|limit|cap|remaining|usage|count|max|trial|free tier|plan|rate limit|throttle" .
rg -n "upload_max|MAX_CONTENT|sizeLimit|MultipartBodyLengthLimit|token bucket|leaky bucket|credits" .
```

---

## Related References

- `references/application/vulnerabilities/business-logic.md`
- `references/application/vulnerabilities/file-upload-download.md`
- `references/application/vulnerabilities/race-conditions.md`
