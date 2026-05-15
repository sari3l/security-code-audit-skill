# Pricing and Accounting Abuse

Use this file when money, credits, balances, fees, exchange rates, quotas with monetary meaning, or settlement math can be attacker-shaped.

---

## High-Risk Surfaces

- client-controlled prices, discounts, exchange rates, tax, or fee fields
- negative values reversing the direction of a balance operation
- rounding, truncation, or precision mismatches
- stale totals, cached signed amounts, or preview helpers treated as source of truth
- cross-currency or unit conversions without invariant checks

---

## Audit Questions

- Which values must be recomputed server-side instead of accepted from the client?
- Can negative, zero, or unusually large values invert or bypass the intended flow?
- Do preview, quote, or signed-state values disagree with the final state-changing function?
- Can two individually small math issues combine into a larger payout, credit, or loss path?

---

## Shape Hint: Client Amount Becomes Settlement Truth

```javascript
// Pseudo-shape only, not a signature.
const total = req.body.total;
await charge(user.card, total);
await createOrder({ userId: user.id, total, items: req.body.items });
```

Do not report by matching this shape alone. Confirm the attacker can influence money, credit, quota, rate, discount, or unit fields; identify the server-side source of truth that should govern settlement; trace the final ledger, payment, refund, or provider callback path; and show a concrete overcharge, undercharge, credit, refund, or reconciliation impact.

---

## Deep Semantic Gate

In `deep` mode, create a `pricing_accounting` gate for each money, credit, balance, refund, discount, exchange-rate, quota-with-monetary-value, or settlement flow.

The gate is not `covered` until the audit records:
- source of truth for every price, amount, fee, discount, tax, rate, balance, credit, debit, refund, quota, and ledger entry
- precision and rounding behavior across preview, quote, invoice, settlement, refund, reconciliation, export, and provider callback paths
- dependency semantics for decimal/money libraries, currency conversion, payment SDK callbacks, database numeric types, serializer coercion, and frontend/server unit conversion
- negative evidence that client-controlled values, negative/zero/large values, stale quotes, signed-state replay, mixed units, or provider retry behavior cannot create profit or loss
- proof obligations for external provider behavior, FX source, tax/rate source, or runtime configuration that cannot be verified locally

If source of truth or rounding behavior cannot be reconciled through final settlement, keep the gate `partial` and create coverage debt.

---

## Grep Starting Points

```bash
rg -n "price|amount|discount|fee|tax|rate|exchange|balance|credit|debit|refund|total|subtotal|round|precision" .
rg -n "Decimal|BigDecimal|float|double|money|currency|quote|preview|invoice|ledger|settle|reconcile" .
```

---

## Related References

- `references/application/vulnerabilities/business-logic.md`
- `references/application/vulnerabilities/mass-assignment.md`
- `references/application/vulnerabilities/race-conditions.md`
