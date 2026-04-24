# MyBatis Security Reference

## Identification Features

```bash
grep -r "mybatis\|mybatis-plus" --include="*.xml" --include="*.properties" --include="*.yml"
find . -name "*Mapper.xml" -o -name "*Mapper.java"
grep -r "@Mapper\|BaseMapper" --include="*.java" --include="*.kt"
grep -r '\${\|#\{' --include="*.xml"
```

Common file patterns: `mapper/` XML files, `*Mapper.xml`, `*Mapper.java`, `application.yml`.

---

## Critical Review Rule

`#{}` is parameter binding.

`${}` is raw string substitution.

Treat `${}` in SQL fragments as high priority unless the value is derived from a strict allowlist.

---

## High-Risk Framework Surfaces

### 1. `${}` Injection

- WHERE clauses
- ORDER BY, GROUP BY, LIMIT, OFFSET
- table names, column names, join fragments

### 2. Dynamic SQL Blocks

- `<if>`, `<choose>`, `<foreach>`, and reusable fragments hiding `${}`
- mapper XML that looks safe at the method level but concatenates fragments underneath

### 3. MyBatis-Plus Wrappers

- `.last()`, `.apply()`, raw SQL append helpers
- dynamic sort or field selection passed through wrappers

---

## Dangerous Patterns

```xml
<select id="findUser">
  SELECT * FROM users WHERE id = ${id}
</select>

<select id="listUsers">
  SELECT * FROM users ORDER BY ${sortColumn}
</select>
```

Safer:

```xml
<select id="findUser">
  SELECT * FROM users WHERE id = #{id}
</select>
```

---

## Detection Commands

```bash
grep -rn '\${' --include="*.xml"
grep -rn 'ORDER BY \\${|GROUP BY \\${|LIMIT \\${|OFFSET \\${|FROM \\${' --include="*.xml"
grep -rn '\.last\(|\.apply\(|Wrapper|QueryWrapper|LambdaQueryWrapper' --include="*.java" --include="*.kt"
```

---

## Audit Questions

- Is `${}` used because the fragment cannot be parameterized, or just for convenience?
- Are sort fields and table names allowlisted in Java/Kotlin before reaching the mapper?
- Do dynamic XML branches hide rare but exploitable raw substitution paths?
- Are wrapper helpers appending SQL after an otherwise safe query builder chain?
