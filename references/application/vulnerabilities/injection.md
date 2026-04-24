# Injection Vulnerabilities

Use this file as the C1 overview and routing layer.

Injection flaws happen when untrusted input changes the structure, grammar, or execution path of an interpreter-like sink instead of remaining inert data.

This category is intentionally broad, so do not stop here. Once you identify the sink family, load the deeper module for that family.

---

## Audit Model

Use `core/bidirectional-tracing.md` as the tracing contract for all injection-like issues.

`source -> transformation -> sink`

Then ask:
- which side is higher signal to enumerate first: candidate sources or candidate sinks?
- which shared helper, parser, wrapper, or policy gate is the likely join point?
- does the next search step narrow a concrete hypothesis, or only expand generic fan-out?
- does attacker input reach a parser, interpreter, or object materializer?
- where do decoding, normalization, reparsing, or grammar changes happen before the sink?
- are values separated from structure?
- are identifiers, modes, or types constrained by allowlists?
- does any legacy or versioned path skip the safer wrapper?
- would the same input be interpreted differently by another layer even if the visible payload changes?

---

## Sink Families And Next Modules

### SQL And ORM Escape Hatches

- raw SQL strings
- ORM helpers such as `raw`, `query`, `statement`, `find_by_sql`, `FromSqlRaw`
- dynamic identifiers and sort clauses

Load:
- `references/application/vulnerabilities/sql-injection.md`
- `references/application/exploits/sql-injection.md`

### OS Commands And Process Invocation

- `system`, `exec`, `subprocess(..., shell=True)`, `Runtime.exec`, `Process.Start`
- archive, image, backup, git, curl, and DNS wrapper utilities

Load:
- `references/application/vulnerabilities/command-injection.md`
- `references/application/exploits/command-injection.md`

### Unsafe Deserialization And Object Materialization

- `pickle`, `marshal`, `ObjectInputStream`, `BinaryFormatter`, `unserialize`
- polymorphic JSON/XML/YAML parsing with attacker-controlled types

Load:
- `references/application/vulnerabilities/deserialization.md`

### Template, Expression, And Dynamic Code Evaluation

- SpEL, Jinja/Twig/ERB evaluation, `eval`, `Function`, `instance_eval`
- user-controlled template bodies or raw expression interpolation

Load:
- `references/application/vulnerabilities/xss-templates.md`
- relevant language/framework modules

### Other Parser-Like Queries

- NoSQL operator injection
- LDAP filters
- XPath expressions
- search DSL and full-text query syntax

Keep using this overview plus the language/framework modules until a deeper specialist file exists.

---

## Cross-Cutting Misses

- parameterization protects values, not identifiers or control clauses
- "internal" admin, support, reporting, or legacy API routes often use weaker helpers
- stored data may become second-order injection later
- no-shell process invocation can still be vulnerable through argument smuggling
- object deserialization may be reachable through sessions, queues, import/export, or SSO flows
- public POCs are probes for structure-changing interpretation, not the definition of the bug

---

## What To Enumerate First

1. every route, job, CLI, webhook, consumer, or scheduled task receiving external input
2. every sink that executes, parses, renders, or materializes structured input
3. every shared raw-query helper, shell wrapper, deserializer, and template helper
4. every versioned or legacy path that may bypass newer protections

One confirmed instance usually means there are more. Exhaust the pattern before moving on.

---

## Grep Starting Points

```bash
grep -rn 'query\\(|execute\\(|raw\\(|statement\\(|createQuery\\(|FromSqlRaw' .
grep -rn 'system\\(|exec\\(|shell=True|Process\\.Start|Runtime\\.getRuntime\\(\\)\\.exec' .
grep -rn 'pickle\\.loads|ObjectInputStream|BinaryFormatter|unserialize\\(|yaml\\.load' .
grep -rn 'eval\\(|Function\\(|parseExpression\\(|ERB\\.new|render inline:' .
grep -rn 'orderByRaw|whereRaw|Arel\\.sql|ORDER BY .*\\+' .
```

---

## Related References

- `references/application/vulnerabilities/sql-injection.md`
- `references/application/vulnerabilities/command-injection.md`
- `references/application/vulnerabilities/deserialization.md`
- `references/application/vulnerabilities/xss-templates.md`
