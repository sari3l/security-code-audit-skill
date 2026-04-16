# Deserialization Vulnerabilities

Unsafe deserialization happens when untrusted data is decoded into executable object graphs, dangerous types, or privileged internal state.

The impact is not limited to code execution:
- remote code execution through gadget chains or magic methods
- authentication or session forgery
- privilege or state manipulation through over-trusted object fields
- denial of service through recursive or oversized payloads

---

## Where It Appears

- native object deserializers such as `pickle`, `marshal`, `ObjectInputStream`, `BinaryFormatter`, `unserialize`
- framework features that store sessions, ViewState-like state, or cache blobs on the client
- message queues, background jobs, and RPC handlers crossing trust boundaries
- polymorphic JSON/XML/YAML binding with attacker-controlled type metadata
- signed blobs that are still attacker-supplied and decoded into rich object types

---

## High-Risk Patterns

- deserializing untrusted bytes into arbitrary classes
- enabling polymorphic type resolution for client-controlled payloads
- trusting signed or encrypted blobs as "safe" without constraining decoded types
- validating a blob as plain data and later reparsing it into richer runtime types or privileged state
- one layer reduces schema while a later converter, hook, or reviver reintroduces executable or authority-bearing structure
- assuming internal message channels are trusted when any upstream producer is attacker-controlled
- loading YAML/XML/JSON with object constructors instead of plain data types

---

## Commonly Missed Cases

- the sink is hidden in middleware, session helpers, queue workers, or SSO integrations
- signed cookies or tokens become dangerous once the signing key leaks or is weak
- JSON libraries can become deserialization sinks through `@type`, `$type`, or custom converters
- deserialization is often reachable in admin import/export endpoints, not just public APIs
- "legacy compatibility" code paths may still accept unsafe serialized formats
- signature or encryption checks prove origin but not safe type materialization
- one parser reads a plain map while a downstream reviver, mapper, or framework hook turns it back into rich objects

## Routing Boundary

Route here when attacker input is decoded into rich objects, polymorphic types, or privileged internal state.

Stay in:
- `mass-assignment.md` when the issue is plain DTO or field overreach without object materialization
- `authentication.md` when the main failure is token verification or session trust without rich-object decoding
- `business-logic.md` when the decoded state is only one step in a larger workflow or accounting abuse chain

---

## Root-Cause Lens

Do not define deserialization only by gadget-chain payloads.

Define it by the semantic failure:
- attacker-controlled bytes or structured data cross from inert data into richer runtime objects or privileged internal state
- one layer believes the content is safe because it was signed, schema-checked, or previously reduced
- a later parser, mapper, converter, or reviver restores dangerous type, behavior, or authority

This means review should focus on:
- where plain data becomes typed objects, hooks, magic methods, or privileged session state
- whether every decode stage preserves the same constrained schema
- whether transport safety, signing, or encryption is being confused with safe materialization

The payload is only the probe.
The root cause is materialization-boundary drift.

---

## Dangerous Patterns

```python
obj = pickle.loads(base64.b64decode(request.cookies["profile"]))
yaml.load(body, Loader=yaml.Loader)
```

```java
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
Object obj = in.readObject();
```

```php
$session = unserialize($_COOKIE["session"]);
```

```csharp
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);
```

```javascript
JSON.parse(body, reviveToClass)
```

---

## Safe Patterns

- decode untrusted input into primitive DTOs, not arbitrary runtime objects
- use safe serializers that do not honor attacker-controlled type metadata
- allowlist concrete types where polymorphism is unavoidable
- rotate away from unsafe legacy formats instead of wrapping them with more trust
- treat signed state as untrusted input unless the decoded schema is tightly constrained

---

## Audit Questions

- Can an attacker influence bytes or structured data entering a deserializer?
- Does the deserializer instantiate arbitrary classes, magic methods, or custom converters?
- Are there legacy session, SSO, queue, or import formats still accepted?
- Is signed or encrypted state decoded into rich objects after verification?
- Does any later reviver, mapper, or hook reintroduce type or authority after an earlier schema check?
- Can the same sink also trigger state corruption even if RCE is not reachable?

---

## Grep Starting Points

```bash
grep -rn 'pickle\\.loads|marshal\\.loads|yaml\\.load|jsonpickle|dill' .
grep -rn 'ObjectInputStream|readObject\\(|XMLDecoder|XStream|enableDefaultTyping|@JsonTypeInfo' .
grep -rn 'unserialize\\(|maybe_unserialize\\(|__wakeup|__destruct' .
grep -rn 'BinaryFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling|\\$type' .
grep -rn 'session|viewstate|remember_me|queue|consumer|deserialize' .
```

---

## Related References

- `references/application/vulnerabilities/injection.md`
- `references/application/exploits/deserialization.md`
- `references/application/languages/java.md`
- `references/application/languages/python.md`
- `references/application/languages/php.md`
- `references/application/languages/dotnet.md`
