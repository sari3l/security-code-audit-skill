# Dynamic Code Evaluation

Dynamic evaluation turns strings, expressions, templates, modules, or serialized structures into executable behavior. Treat every evaluator as a dangerous capability and enumerate it before deciding whether the current input shape is directly injectable.

## Enumerate First

- Python `eval`, `exec`, `compile`, `__import__`, `importlib.import_module`, and wrappers around them
- JavaScript `eval`, `Function`, string timers, VM/runtime compilation, and dynamic imports from untrusted selectors
- expression and rule engines such as SpEL, OGNL, MVEL, JEXL, EL, and embedded scripting runtimes
- framework helpers that compile templates, predicates, filters, queries, or user-defined automation
- aliases, re-exports, `getattr`/reflection, callback registries, and shared helpers hiding an evaluator

Record every occurrence in `dangerous-capabilities.jsonl` using `core/dangerous-capability-census.md`.

## Trace Each Component Separately

For each evaluator, identify:

- the API/CLI/queue/config source and all attacker-controlled fields, types, nesting, duplicate-field behavior, and parser hooks
- the callable or module selector and the exact property constrained by any allowlist
- the code or expression text, including how values are serialized or represented
- globals, locals, builtins, imports, registered functions, and evaluator namespace
- every selected handler and its downstream use of parameters
- authentication, task-level authorization, parameter schemas, resource limits, and observable side effects

Do not let a selector allowlist close parameter or handler semantics it does not protect.

## API-Reachable Python `eval`

For code shaped like:

```python
task_name = request.get_json()["task_name"]
params = request.get_json()["params"]
if task_name not in ALLOWED_TASK_NAME:
    deny()
eval(f"{task_name}(**{params})")
```

default Python `dict.__repr__` normally keeps string payloads inside escaped string literals, so this snippet alone may not prove direct expression escape. That fact affects maturity, not discovery or reporting.

Required result:

- mark the evaluator and API reachability as confirmed facts
- create a report-visible `high_risk_alert` when direct injection is unproven
- inspect whether the JSON provider or mapping type is customized
- verify the allowlist is static, exact, and unpolluted
- trace every allowlisted handler and every parameter into secondary evaluators, shells, templates, deserializers, files, networks, and privileged operations
- review task-level authorization and per-task parameter schemas

A failed string payload, ordinary `dict` escaping, or a callable-name allowlist is not enough for `negative_closed` while attacker-controlled API data still reaches the evaluator.

## Confirmation And Closure

Use `confirmed_finding` when untrusted data changes executed code, selects an unauthorized capability, exposes a dangerous evaluator namespace, or reaches a downstream execution primitive with concrete impact.

Use `negative_closed` only when the occurrence is unreachable from untrusted boundaries or the evaluated program is fixed and all variable data is handled through a non-executable typed channel, with consumers and wrappers inspected. Prefer removing the evaluator even when isolation appears sound.

## Minimal Fixes

- replace string evaluation with a static map from allowed identifiers to callable objects
- validate each operation with an explicit schema and task-level authorization
- pass data as ordinary values, not as source-code text
- use a purpose-built parser with a deliberately limited grammar when expressions are a real product requirement
- isolate unavoidable evaluators with a minimal namespace, resource limits, and process boundaries; do not present isolation as equivalent to removal

## Search Starters

```bash
rg -n --glob '*.py' '(?<![[:alnum:]_.])(eval|exec|compile)\s*\(|builtins\.(eval|exec|compile)\s*\(|getattr\s*\([^,]+,\s*["'"'](eval|exec|compile)["'"']'
rg -n --glob '*.py' '__import__\s*\(|importlib\.import_module\s*\('
rg -n --glob '*.{js,jsx,ts,tsx,mjs,cjs}' '\beval\s*\(|\bFunction\s*\(|set(Time|Inter)val\s*\(\s*["'"']'
rg -n 'parseExpression|SpelExpressionParser|OGNL|MVEL|JEXL|ScriptEngine|render_template_string'
```

Treat these as seed searches. Inspect aliases, wrappers, generated code, and framework registration paths manually.
