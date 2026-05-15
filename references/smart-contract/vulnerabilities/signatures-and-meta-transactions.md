# Signatures And Meta-Transactions

Use this file for permit flows, EIP-712 signing, off-chain approvals, relayed actions, and any path where authority arrives through signatures instead of direct calls.

---

## Enumerate First

- `permit`, `permit2`, `ecrecover`, `ECDSA`, `DOMAIN_SEPARATOR`, `nonces`
- meta-transaction entry points and trusted forwarders
- off-chain order, approval, claim, mint, or withdraw signatures
- any signer-controlled config, allowlist, price, or admin action
- frontend, Safe app, relayer, keeper, and hardware-wallet paths that display or transform signed intent before broadcast

---

## High-Risk Patterns

- missing or reusable nonces
- missing expiry or block deadline
- chain ID, verifying contract, or domain separation missing from signed data
- signature bound to the wrong actor or missing caller/beneficiary binding
- `abi.encodePacked` collisions in signed payloads
- trusted forwarder or relayer assumptions that are not actually enforced
- same signature valid across contracts, chains, or contexts
- UI-displayed signing intent that differs from the EIP-712 fields, raw calldata, spender, proxy target, or final beneficiary
- blind signing or opaque multisig signing for high-value approvals, permit2 allowances, upgrades, bridge messages, or batch operations
- relayer or meta-tx failures treated as normal retry noise, hiding signer replay, dropped nonce, wrong domain, or unexpected target behavior

---

## Meta-Tx Specific Checks

- who is treated as the real sender
- whether replay is possible through relayer-controlled metadata
- whether gas sponsorship or fee logic creates hidden privilege
- whether signer intent changes if calldata is wrapped, forwarded, or partially decoded
- whether the displayed message, simulation, or Safe transaction summary covers the actual target, value, calldata, delegatecall flag, allowance, and beneficiary
- whether relayer errors, failed simulations, and unexpected replacement transactions are logged and alertable instead of silently retried

---

## Audit Questions

- Can the same signature be used twice?
- Can it be replayed on another chain, contract, vault, or market?
- Is the beneficiary bound tightly enough to prevent redirection?
- Does the relayer or forwarder gain authority it should not have?
- Are signer rotation, domain updates, and nonce invalidation handled safely?
- Can a frontend, transaction builder, relayer, or Safe app cause a user or admin to sign valid data with different semantics than they intended?
- Are failures in relayed or meta-transaction flows observable enough to catch domain drift, nonce desync, replay attempts, or malicious target substitution?

---

## Shape Hint: Signed Intent Missing Beneficiary Binding

```solidity
// Pseudo-shape only, not a signature.
bytes32 digest = hashTypedData(amount, nonce, deadline);
address signer = ECDSA.recover(digest, sig);
_withdrawFor(signer, msg.sender, amount);
```

Do not report by matching this shape alone. Confirm the signature omits a context that matters to signer intent, such as beneficiary, caller, chain, contract, action, nonce, deadline, spender, target, or relay context; prove the same signed data can authorize an unintended action; and show asset movement, approval, claim, mint, withdrawal, or privilege impact.

---

## Remediation Notes

- Do not recommend "add a nonce" as the whole fix if replay is actually caused by missing domain separation, missing beneficiary/caller binding, or wrong signer scope.
- Minimal fixes should bind signed intent to the exact context that matters: chain, contract, action, beneficiary, amount, deadline, and nonce as needed by the protocol flow.
- Preserve the intended signing UX. A fix that invalidates legitimate relaying or breaks all existing signed payloads may still be correct, but it is not a "minimal" fix unless the report says that explicitly.
- If already-issued signatures remain valid after the code patch, call out the migration or revocation requirement instead of implying the issue is closed by code alone.
- When UI or relayer compromise is part of the path, prefer binding and on-chain validation of signer intent over a process-only instruction to "verify the frontend."
- State the exact impossible post-fix condition, such as: "a valid signature can no longer be replayed across contracts, chains, beneficiaries, or relay contexts."
