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
