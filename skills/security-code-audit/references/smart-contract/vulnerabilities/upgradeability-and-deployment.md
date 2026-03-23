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
