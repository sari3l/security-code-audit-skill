# Trust And Privilege

Start here when ownership, admin rights, signer authority, rescue flows, initialization, or governance assumptions decide who can move funds or mutate critical state.

---

## Enumerate First

- all privileged roles: owner, admin, operator, upgrader, pauser, guardian, rescuer, keeper, signer
- how each role is granted, revoked, and rotated
- whether proxy admin and implementation auth are separated correctly
- whether constructor assumptions were moved into `initialize`
- whether emergency or recovery paths bypass ordinary accounting

---

## High-Risk Patterns

- unprotected `initialize`, `reinitialize`, or setup helpers
- `onlyOwner` or `AccessControl` coverage missing on critical functions
- `tx.origin` used for privileged checks
- rescuer, sweep, emergency, or admin functions that can move user funds
- signer rotation or admin change flows with no delay, no quorum, or weak caller checks
- proxy admin and app admin sharing one overly-powerful actor without controls

---

## Audit Questions

- Can a non-admin become admin, upgrader, or signer?
- Can initialization or recovery run twice or from the wrong address?
- Can any privileged path bypass caps, pause guards, user accounting, or normal settlement?
- Are governance, timelock, multisig, or operator assumptions enforced on-chain, or just documented off-chain?
- Can deployment or upgrade sequencing leave a temporary takeover window?

---

## Review Moves

- map every state-changing privileged function before reviewing business logic
- compare intended role model with actual modifiers and storage fields
- trace privilege through proxies, factories, registries, and signers
- document any privileged path that can drain, freeze, or rewrite user state
