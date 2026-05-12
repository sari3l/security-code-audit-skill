# SQL Injection Vulnerabilities

SQL injection happens when untrusted input changes SQL structure instead of remaining a bound value.

Treat SQLi as a family, not one pattern:
- value injection in `WHERE`, `INSERT`, `UPDATE`, and `DELETE`
- identifier injection in column, table, schema, and alias names
- clause injection in `ORDER BY`, `GROUP BY`, `LIMIT`, `OFFSET`, and dynamic filters
- second-order SQLi where stored data becomes dangerous later
- ORM escape-hatch injection through raw query helpers

---

## Where It Appears

- hand-built SQL strings with concatenation or interpolation
- ORM escape hatches such as `raw`, `query`, `statement`, `find_by_sql`, `FromSqlRaw`
- report builders, search endpoints, exports, and admin tooling
- bulk update or import jobs that build column lists dynamically
- migration, analytics, or background task code treated as "internal"

---

## High-Risk Patterns

- interpolating request data directly into SQL strings
- assuming parameterization protects identifiers or sort fields
- mixing safe placeholders with unsafe string-built fragments
- accepting client-controlled filter operators or raw fragments
- reusing stored user input later in reporting or scheduled jobs

---

## Commonly Missed Cases

- `ORDER BY` and sort direction values are usually concatenated, not bound
- JSON/GraphQL filters may flow into raw SQL fragments through helpers
- second-order SQLi often appears after moderation, approval, or import
- "read-only" reporting endpoints still expose schema and sensitive data
- a single shared repository helper can fan out to many endpoints

---

## Dangerous Patterns

```python
sql = f"SELECT * FROM users WHERE email = '{email}'"
cursor.execute(sql)
```

```javascript
await db.query(`SELECT * FROM users ORDER BY ${req.query.sort}`)
```

```java
String sql = "SELECT * FROM orders WHERE tenant_id = " + tenantId;
statement.executeQuery(sql);
```

```php
$sql = "UPDATE users SET role = '$role' WHERE id = $id";
DB::statement($sql);
```

```csharp
var sql = $"SELECT * FROM Users WHERE Name = '{name}'";
await context.Users.FromSqlRaw(sql).ToListAsync();
```

---

## Safe Patterns

- bind all data values with prepared statements or framework parameter APIs
- allowlist identifiers such as sortable columns or table choices
- map client sort/filter inputs to fixed server-side query fragments
- keep raw SQL isolated behind reviewed helpers with narrow safe inputs
- treat stored content as untrusted when reused in later queries

---

## Audit Questions

- Can the attacker control values, identifiers, operators, or whole clauses?
- Does the query builder ever concatenate `ORDER BY`, `LIMIT`, or raw filter fragments?
- Are there alternate API versions or admin/reporting endpoints using different query code?
- Can stored user data later flow into analytics, exports, or scheduled SQL jobs?
- Does one unsafe repository helper affect multiple routes?

---

## Deep Semantic Gate

In `deep` mode, create a `sql_structure_control` gate for each query-builder family, raw SQL helper, reporting/export path, dynamic-filter system, or repository layer that accepts user-influenced input.

The gate is not `covered` until the audit records:
- every source that can influence SQL values, identifiers, operators, clauses, filters, sort order, table names, schemas, aliases, limits, offsets, or raw fragments
- every sink family: raw query APIs, ORM escape hatches, dynamic report builders, analytics jobs, migrations/imports, scheduled SQL, and stored-data reuse
- dependency semantics for the database driver, ORM, query builder, placeholder API, identifier quoting, raw fragment API, and framework filter binding
- explicit separation of value parameterization from identifier/clause allowlisting; parameterized values do not prove dynamic identifiers, `ORDER BY`, `GROUP BY`, `LIMIT`, or operators are safe
- negative evidence showing that each dynamic identifier, sort field, operator, filter key, and raw fragment is mapped to fixed server-side SQL or otherwise constrained before query construction
- proof obligations for generated SQL, stored second-order flows, or runtime-only query builders that cannot be inspected statically

Record design/implementation conflicts when:
- documentation or code comments claim "parameterized queries" while the dangerous control point is an identifier, operator, sort, or raw fragment
- an ORM helper appears safe at one call site but accepts raw fragments or disabled escaping at another
- admin/reporting/internal jobs reuse user-controlled stored values under a different trust assumption

If dynamic SQL structure cannot be reconciled from source to final query text, keep the gate `partial` or `blocked` and create coverage debt.

---

## Grep Starting Points

```bash
grep -rn 'SELECT .*\\+|INSERT .*\\+|UPDATE .*\\+|DELETE .*\\+' .
grep -rn 'f\"SELECT|f\"INSERT|f\"UPDATE|f\"DELETE|format\\(.*SELECT' .
grep -rn 'query\\(|execute\\(|executemany\\(|createQuery\\(|createNativeQuery\\(' .
grep -rn 'raw\\(|whereRaw\\(|orderByRaw\\(|statement\\(|find_by_sql|FromSqlRaw|ExecuteSqlRaw' .
grep -rn 'ORDER BY|GROUP BY|LIMIT|OFFSET' .
```

---

## Related References

- `references/application/exploits/sql-injection.md`
- `references/application/vulnerabilities/injection.md`
- `references/application/frameworks/java_mybatis.md`
