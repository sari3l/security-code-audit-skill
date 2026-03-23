# Application Profile

Default target profile for web apps, APIs, services, and mixed backend/full-stack repos.

Use when the primary audit shape is still traditional application security with auth, authz, input handling, data exposure, config, dependencies, and client/server trust boundaries.

---

## Progress Labels

### Quick

- `[3/6] Triage critical control surfaces`
- `[4/6] Check secrets, config, and dependency red flags`
- `[5/6] Minimal verification, history, and report prep`

### Standard

- `[3/6] Audit control surfaces`
- `[4/6] Audit data, client, dependency, and infra surfaces`
- `[5/6] Coverage, history, and prioritization`

### Deep

- `[3/6] Deep control-surface analysis`
- `[4/6] Exhaustive data, dependency, and infra review`
- `[5/6] Attack chains, strict coverage, and history`

---

## Emphasis Notes

- start with control-heavy categories such as injection, authentication, authorization, and mass assignment
- then move through data exposure, config, dependencies, cryptography, SSRF, logging, and infrastructure
- use attack-chain and business-logic language where it fits application behavior

---

## Audit Routing

- use `references/application/index.md` as the primary knowledge domain router
- use `references/application/vulnerabilities/index.md` as the main application methodology map
- load framework, artifact, dependency, and exploit modules only when the observed surface matches
