# Trust And Privilege

Start here when ownership, admin rights, signer authority, rescue flows, initialization, or governance assumptions decide who can move funds or mutate critical state.

---

## Enumerate First

- all privileged roles: owner, admin, operator, upgrader, pauser, guardian, rescuer, keeper, signer
- how each role is granted, revoked, and rotated
- whether proxy admin and implementation auth are separated correctly
- whether constructor assumptions were moved into `initialize`
- whether emergency or recovery paths bypass ordinary accounting
- which pause, rescue, sweep, recover, queue, and claim paths can still accept fresh user assets or create new pending exposure
- whether critical privilege transitions emit monitorable events or expose a standard observable state

---

## High-Risk Patterns

- unprotected `initialize`, `reinitialize`, or setup helpers
- `onlyOwner` or `AccessControl` coverage missing on critical functions
- `tx.origin` used for privileged checks
- rescuer, sweep, emergency, or admin functions that can move user funds
- custom pause or emergency controls that lack standard events, observable state, or consistent gating across equivalent paths
- "emergency exit" helpers that still accept new assets, create new pending state, or route funds into a compromised dependency during pause
- functions named like exit, emergency, queue, or claim that accept `msg.value`, take fresh user assets, or create a new external queue/request state should be treated as entry-like for pause review
- recovery or sweep helpers that can touch transient user funds before settlement fully closes
- signer rotation or admin change flows with no delay, no quorum, or weak caller checks
- proxy admin and app admin sharing one overly-powerful actor without controls

---

## Audit Questions

- Can a non-admin become admin, upgrader, or signer?
- Can initialization or recovery run twice or from the wrong address?
- Can any privileged path bypass caps, pause guards, user accounting, or normal settlement?
- If a privileged recovery path is claimed to endanger user assets, what reachable post-settlement state actually leaves those user-owned assets in the contract?
- Do pause semantics distinguish between true exit or claim paths and helpers that accept fresh assets or create new protocol exposure?
- Does any supposedly "exit-only" helper still take new funds from the caller or create a new pending claim, queue position, or external request during pause?
- Do pause, unpause, rescue, recovery, or ownership-transfer actions emit events that monitoring and governance tooling can rely on?
- Did a remediation add a new privileged helper or fallback path that silently reopens the original trust boundary?
- Are governance, timelock, multisig, or operator assumptions enforced on-chain, or just documented off-chain?
- Can deployment or upgrade sequencing leave a temporary takeover window?

---

## Review Moves

- map every state-changing privileged function before reviewing business logic
- map pause, queue, claim, sweep, recover, and rescue paths separately from ordinary user exits
- compare intended role model with actual modifiers and storage fields
- treat custom pause implementations as first-class review surfaces; compare eventing, public observability, and gating consistency with standard `Pausable` expectations
- trace privilege through proxies, factories, registries, and signers
- document any privileged path that can drain, freeze, or rewrite user state
