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
- validation performed with one URL parser while the actual fetch uses another parser or redirect stack
- hostname, scheme, or port checks applied before canonicalization of userinfo, dots, IDNA, IPv6, or alternate numeric forms
- following redirects without re-validating destination
- blocking `127.0.0.1` but not decimal, hex, IPv6, or metadata hosts
- support for dangerous schemes such as `file://` or `gopher://`

---

## Commonly Missed Cases

- SSRF through PDF or image rendering, not explicit fetch endpoints
- DNS rebinding after initial validation
- webhook edit vs webhook fire using different validation depth
- server-side HEAD, GET, and DNS checks treated as harmless even when network reachability itself is sensitive
- validators run on raw input while the HTTP client fetches a decoded, normalized, or redirected destination
- proxy settings, service mesh behavior, or internal redirectors change the final target after initial host checks

---

## Root-Cause Lens

Do not define SSRF by a fixed blacklist of localhost strings.

Define it by the semantic failure:
- the destination that is validated is not the destination that is finally reached
- one layer classifies the target as external while another layer resolves or redirects it to an internal resource
- scheme, host, port, path, or DNS meaning changes across parsers, redirects, or network layers

This means review should focus on:
- which parser extracts scheme, host, and port before the request is made
- whether the same canonical destination is revalidated after redirects, DNS resolution, proxy routing, or client normalization
- whether harmless-looking fetch features still provide sensitive reachability, credentials, or trust context

The payload is only the probe.
The root cause is destination-resolution drift.

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
- Which parser and network layer decide the final scheme, host, port, and resolved IP?
- Can validation and fetch operate on different URL representations or redirect chains?
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
