# Signatures And Meta-Transactions

Use this file for permit flows, EIP-712 signing, off-chain approvals, relayed actions, and any path where authority arrives through signatures instead of direct calls.

---

## Enumerate First

- `permit`, `permit2`, `ecrecover`, `ECDSA`, `DOMAIN_SEPARATOR`, `nonces`
- meta-transaction entry points and trusted forwarders
- off-chain order, approval, claim, mint, or withdraw signatures
- any signer-controlled config, allowlist, price, or admin action

---

## High-Risk Patterns

- missing or reusable nonces
- missing expiry or block deadline
- chain ID, verifying contract, or domain separation missing from signed data
- signature bound to the wrong actor or missing caller/beneficiary binding
- `abi.encodePacked` collisions in signed payloads
- trusted forwarder or relayer assumptions that are not actually enforced
- same signature valid across contracts, chains, or contexts

---

## Meta-Tx Specific Checks

- who is treated as the real sender
- whether replay is possible through relayer-controlled metadata
- whether gas sponsorship or fee logic creates hidden privilege
- whether signer intent changes if calldata is wrapped, forwarded, or partially decoded

---

## Audit Questions

- Can the same signature be used twice?
- Can it be replayed on another chain, contract, vault, or market?
- Is the beneficiary bound tightly enough to prevent redirection?
- Does the relayer or forwarder gain authority it should not have?
- Are signer rotation, domain updates, and nonce invalidation handled safely?

---

## Remediation Notes

- Do not recommend "add a nonce" as the whole fix if replay is actually caused by missing domain separation, missing beneficiary/caller binding, or wrong signer scope.
- Minimal fixes should bind signed intent to the exact context that matters: chain, contract, action, beneficiary, amount, deadline, and nonce as needed by the protocol flow.
- Preserve the intended signing UX. A fix that invalidates legitimate relaying or breaks all existing signed payloads may still be correct, but it is not a "minimal" fix unless the report says that explicitly.
- If already-issued signatures remain valid after the code patch, call out the migration or revocation requirement instead of implying the issue is closed by code alone.
- State the exact impossible post-fix condition, such as: "a valid signature can no longer be replayed across contracts, chains, beneficiaries, or relay contexts."
