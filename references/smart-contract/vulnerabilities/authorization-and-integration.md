# Authorization, Asset Flow, And Integration Semantics

Use this module when a role, operator, strategy, adapter, solver, relayer, or
external contract can influence where assets go, how much is moved, or which
state key receives a limit. A valid role check proves who may call a function;
it does not prove that the caller is constrained to the intended capability.

## Capability-to-Asset Matrix

For every privileged or semi-privileged entry point, record the tuple:

```text
(caller/role, action, token, source account, recipient, spender, route/strategy,
 amount, fee/net semantics, state key, phase/deadline)
```

Check each tuple against the intended policy. A role that can choose an
arbitrary recipient, spender, strategy, token, or route has a wider capability
than a role that can merely invoke the action. Check both direct calls and
cross-contract calls where a strategy or adapter forwards the choice.

High-signal cases include:

- approval or allowance helpers that validate the approver but do not constrain
  the spender or token
- restrictive, emergency, or zeroing approval variants that skip the normal
  spender allowlist or share a cooldown key that is broader than the policy
- withdrawal or settlement helpers that validate the caller but take the
  recipient, beneficiary, or destination from untrusted calldata
- trader/operator roles that can invoke a strategy method whose downstream
  `to`, receiver, or token account is caller-selected
- emergency, rescue, sweep, or recovery paths that bypass normal accounting or
  limits for transient or unsettled user funds
- allowlists that constrain a selector or contract but not its arguments,
  delegated target, callback, or downstream token movement

## Execution Context And Target Binding

Treat the caller, the executing address, the code target, and the selected
recipient as separate security dimensions. For EVM delegation, `delegatecall`
preserves `msg.sender` and `msg.value` while executing code against the caller's
storage and address. A check such as `address(this) == VAULT` therefore does not
prove that the original caller is the vault, nor does a strategy allowlist bind
the delegated selector, token, amount, or recipient. Trace the full tuple through
the delegatecall boundary and require the callee to enforce the intended
capability in the context where assets actually move.

Apply the same rule to proxy, plugin, registry, router, and Solana CPI paths:
the configured implementation or program, the account owner/program id, the
active registry entry, and every remaining account must agree with the target
that is actually invoked. A registry value that is checked at the entry point
but ignored by an adapter is not authorization evidence. Record the selected
target, selector/instruction, original caller, execution context, and final
asset account as separate trace checkpoints.

## State Keying And Limits

Reconstruct the key used for every allowance, cooldown, rate limit, nonce,
replay guard, and settlement record. Compare the implementation key with the
policy dimensions. For example, a limit intended per `(token, spender)` cannot
be implemented as one value per `token`; a cooldown intended per user cannot be
shared globally. Review initialization, zeroing, revocation, expiry, and
multi-action or multicall behavior for each key.

When a spender, strategy, adapter, token, or program is removed or quarantined,
re-open every execution path that can still use previously granted authority.
Check whether removal revokes existing allowances/permissions, invalidates
active configuration accounts, blocks disabled tokens at execution time, and
prevents stale registry or remaining-account values from reaching adapters. A
write that only flips `is_supported` or deletes a registry row is incomplete
evidence until all spend, settle, withdraw, and strategy entry points consume
that state.

## Cross-Contract Settlement

Trace both sides of every interface, solver, vault, strategy, adapter, router,
and callback. Verify:

- whether `amountIn` is gross or net of fees
- who computes and who enforces fees, minimum output, slippage, and deadlines
- whether the protocol checks actual pre/post balances rather than trusting a
  nominal return value
- whether decimals, fee-on-transfer, rebasing, wrappers, and non-standard
  return values change the amount received
- whether the external component can redirect a recipient, reuse an intent, or
  settle a different token or route than the signed/requested intent
- whether tests and mocks model the deployed component or silently assume an
  incompatible transfer or fee semantic

If the external implementation or deployment configuration is unavailable,
report the unresolved semantic as an integration assumption and preserve a
proof obligation or coverage debt. Do not infer gross/net behavior from a
function name or a mock that transfers the requested amount verbatim.

## Required Evidence

The trace for a material issue must show the caller, every user-controlled
selector/value, the authorization check, state key, external call, token or
balance delta, and the final violated invariant. A role label, interface
signature, or unit test alone is insufficient evidence.

In `deep` mode, create an `authorization_asset_flow` or
`cross_contract_settlement` deep gate for each applicable family and enumerate
all materially equivalent sibling helpers before closing the gate. Add an
`execution_context_binding` gate for any `delegatecall`, proxy/plugin, registry,
router, or CPI boundary, and a `capability_lifecycle` gate for remove,
quarantine, disable, revoke, or supported-flag flows.

## Regression Traps

Use these as explicit hypotheses when the corresponding shapes appear:

- an approval cooldown or timestamp stored by token only while the policy is
  per spender; test both new approvals and `approve(0)` revocation for every
  spender sharing that token
- an `approveRestrictively` or emergency approval path that bypasses the normal
  spender allowlist; test arbitrary spenders and whether zeroing/revocation is
  delayed by the same cooldown
- a trader or operator role that can call a release, fill, or settle method
  while the downstream `to`, receiver, or token account remains caller-selected
- a vault or strategy forwarding `amountIn` across a solver boundary without
  proving whether the receiving side expects gross, fee-inclusive, or net
  settlement
- a `delegatecall` callee that relies on `address(this)` or an allowlisted code
  target while the original caller controls selector arguments, recipient, or
  token movement
- a checked strategy/program registry whose adapter or CPI instruction invokes a
  fixed or different target, or ignores the active configuration account
- a remove-token, quarantine, or supported-flag update that leaves a sibling
  execution path able to spend the token or use a stale strategy configuration

These are hypothesis seeds, not findings by pattern. Confirm the actual caller,
state key, external implementation, balance delta, and violated invariant.

## Minimal-Fix Guidance

Prefer the narrowest fix that enforces the intended tuple: bind recipient,
spender, token, route, and amount to trusted state or an authenticated intent;
key limits by every policy dimension; and validate actual balance deltas and
fee/net semantics at the integration boundary. Do not solve a missing
authorization constraint by adding a generic role or a selector-only allowlist.
