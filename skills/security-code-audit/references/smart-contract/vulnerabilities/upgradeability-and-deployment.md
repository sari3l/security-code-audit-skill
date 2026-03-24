# Upgradeability And Deployment

Use this file for proxies, beacons, factories, implementation initialization, deployment sequencing, environment assumptions, and admin operational risk.

---

## What To Enumerate

- proxy type: transparent, UUPS, beacon, custom, minimal proxy, diamond, factory-cloned
- who controls upgrades and where that authority lives
- initializer and reinitializer flows
- implementation contracts that can be initialized directly
- storage layout assumptions across versions
- deployment scripts, environment variables, signer setup, and release ordering

---

## High-Risk Patterns

- implementation left initializable
- `upgradeTo` or `upgradeToAndCall` reachable by wrong actor
- storage collision from changed inheritance or slot layout
- upgrade hooks calling external code before protection is established
- deployment scripts assuming one-time sequencing but not enforcing it
- pause or rescue assumptions broken across upgrades

---

## Audit Questions

- Can an attacker initialize the implementation or proxy out of sequence?
- Is upgrade authority stronger than intended, or shared with unrelated admin power?
- Can a new implementation corrupt balances, roles, or accounting through layout mismatch?
- Are deployment or migration steps safe if partially executed, replayed, or front-run?
- Are environment, signer, and RPC assumptions protected from misconfiguration?

---

## Supporting Evidence

- explicit upgrade auth path
- initializer reachability
- storage layout delta
- deployment script sequencing assumptions
- admin key and environment dependency map

---

## Remediation Notes

- Do not recommend a simple `onlyOwner` patch if the real issue is that upgrade authority, initializer reachability, or admin separation is fundamentally wrong.
- Minimal fixes should preserve the intended upgrade and deployment flow while removing the unsafe state transition, for example by locking implementation initialization, tightening upgrade auth, or adding one-time sequencing assertions.
- Avoid remediation that silently bricks proxy upgrades, reinitializers, or rescue flows unless the report explicitly says that shutdown is the least unsafe option.
- When storage layout or migration risk is involved, say so directly. A code patch without a rollout or migration step is not a complete minimal fix for a live deployment.
- State the exact impossible post-fix condition, such as: "an attacker can no longer initialize, upgrade, or migrate the system through an out-of-sequence or overly privileged path."
