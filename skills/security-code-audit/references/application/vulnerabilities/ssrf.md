# Server-Side Request Forgery (SSRF)

SSRF happens when an attacker can influence a server-side request target and use the application as a network pivot.

Impact ranges from:
- internal service discovery
- cloud metadata access
- local file reads through alternate schemes
- credential theft from service-to-service trust

---

## What To Enumerate First

1. URL fetchers, webhooks, previews, PDF renderers, image importers, crawlers, and metadata import flows
2. every HTTP client wrapper or helper
3. redirect handling and DNS resolution logic
4. allowed-scheme and allowed-host validation code

---

## High-Risk Patterns

- user-supplied URLs passed directly to HTTP client libraries
- allowlists based only on string prefix or hostname text
- following redirects without re-validating destination
- blocking `127.0.0.1` but not decimal, hex, IPv6, or metadata hosts
- support for dangerous schemes such as `file://` or `gopher://`

---

## Commonly Missed Cases

- SSRF through PDF or image rendering, not explicit fetch endpoints
- DNS rebinding after initial validation
- webhook edit vs webhook fire using different validation depth
- server-side HEAD, GET, and DNS checks treated as harmless even when network reachability itself is sensitive

---

## Safe Patterns

- strict allowlists by resolved IP or tightly-scoped domains
- re-validation after redirects and DNS resolution
- blocking loopback, RFC1918, link-local, and metadata ranges
- separate clients or egress controls for internal and external traffic

---

## Audit Questions

- Which hosts, schemes, and ports can the server reach because of this feature?
- Is destination validation based on string parsing or actual resolution?
- Are redirects and alternate address encodings handled?
- Can the feature hit metadata endpoints or service mesh/admin ports?

---

## Grep Starting Points

```bash
grep -rn 'http\\.get|requests\\.|URLSession|HttpClient|RestTemplate|WebClient|reqwest|Net::HTTP|curl_init|file_get_contents' .
grep -rn 'redirect|follow_redirects|AllowAutoRedirect|CURLOPT_FOLLOWLOCATION' .
grep -rn '169\\.254\\.169\\.254|metadata\\.google\\.internal|localhost|127\\.0\\.0\\.1|::1' .
```

---

## Related References

- `references/application/exploits/ssrf.md`
- `references/application/vulnerabilities/api-security.md`
