# API Specification and Collection Review

This is an artifact and recon module, not the runtime API weakness methodology. Use it to extract hidden surface and stale auth assumptions from schemas, specs, and collections, then route confirmed runtime issues into `references/application/vulnerabilities/api-security.md`, `authorization.md`, or related modules.

API descriptions are often treated as documentation, but OpenAPI, Swagger, Postman, Insomnia, GraphQL schema files, and similar artifacts frequently reveal hidden attack surface, stale auth assumptions, exposed examples, and version drift.

---

## What To Enumerate First

1. OpenAPI, Swagger, Postman, Insomnia, GraphQL schema, and AsyncAPI files
2. every documented path, method, tag, version, server URL, and security scheme
3. example requests, example responses, mock payloads, and environment variables
4. deprecated, internal, admin, debug, or beta endpoints that still appear in collections or schemas
5. differences between the spec and the implemented routes

---

## High-Risk Patterns

- admin, internal, or debug routes published in spec or collection files
- old API versions retained in collections after authz rules changed elsewhere
- bearer tokens, API keys, basic auth creds, cookies, or internal hosts embedded in examples or environments
- weak or missing security scheme declarations that do not match runtime enforcement
- batch, bulk, and hidden mutation endpoints exposed in collections but not normal docs
- schema examples leaking production-like PII, secrets, or internal identifiers
- GraphQL introspection or mutation schema artifacts revealing privileged object models
- SDK or collection variables pointing at staging, internal, or metadata endpoints

---

## Audit Questions

- Does the spec list endpoints that the recon phase would otherwise miss?
- Are deprecated or old-version endpoints still reachable and less protected?
- Do examples or environments expose real secrets, internal IPs, or hidden routes?
- Does the declared auth model match the implemented auth model?
- Are dangerous bulk, admin, or debugging operations discoverable only through artifacts?
- Does the schema expose object relationships that make BOLA/IDOR or mass assignment easier to find?

---

## Grep Starting Points

```bash
rg -n "openapi:|swagger:|paths:|components:|securitySchemes:|servers:|deprecated:|x-internal" .
rg -n "postman_collection|info\":|item\":|event\":|auth\":|bearer|apikey|basic" .
rg -n "graphql|schema|type Query|type Mutation|directive|introspection" .
rg -n "token|api[_-]?key|authorization|cookie|secret|password|internal|staging|admin|debug" .
```

---

## Review Strategy

1. Treat API specs and collections as independent recon sources, not just nice-to-have docs.
2. Diff documented endpoints, parameters, and auth declarations against real code.
3. Extract hidden versions, admin paths, and environment variables into the surface profile.
4. Feed newly discovered routes back into authz, API-version, and data-exposure review.

---

## Related References

- `references/application/vulnerabilities/api-security.md`
- `references/application/vulnerabilities/authorization.md`
- `references/application/vulnerabilities/mass-assignment.md`
- `references/application/vulnerabilities/sensitive-hardcoding.md`
