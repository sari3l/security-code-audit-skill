# Framework Modules Index

Framework references use a `language_framework.md` naming convention so the load path is explicit and stable.

Use these files for:
- framework fingerprinting
- framework-specific dangerous defaults
- framework-specific sinks, helpers, and middleware gaps

General language risks still live in `references/application/languages/`.

---

## Python

| Framework | File | Focus |
|-----------|------|-------|
| Flask | `references/application/frameworks/python_flask.md` | debug RCE, SSTI, Jinja trust boundaries, session signing |
| Django | `references/application/frameworks/python_django.md` | `raw()`, `mark_safe`, DRF authz, settings hardening |
| FastAPI | `references/application/frameworks/python_fastapi.md` | dependency injection, Pydantic binding, response-model leaks |

## JavaScript / TypeScript

| Framework | File | Focus |
|-----------|------|-------|
| Express | `references/application/frameworks/javascript_express.md` | `eval`, child_process, session config, prototype pollution |
| Next.js | `references/application/frameworks/javascript_nextjs.md` | server/client boundary, API routes, SSR data flows |
| Koa | `references/application/frameworks/javascript_koa.md` | middleware order, `ctx` trust, file/path helpers |
| NestJS | `references/application/frameworks/typescript_nestjs.md` | guards, pipes, DTO validation, websocket/API parity |

## Java / Kotlin

| Framework | File | Focus |
|-----------|------|-------|
| Spring | `references/application/frameworks/java_spring.md` | Actuator, SpEL, deserialization, security config |
| MyBatis | `references/application/frameworks/java_mybatis.md` | `${}` injection, dynamic SQL fragments, mapper XML review |
| Kotlin Spring | `references/application/frameworks/kotlin_spring.md` | Kotlin data-class binding, Spring Security parity, nullability assumptions |

## Go

| Framework | File | Focus |
|-----------|------|-------|
| Gin | `references/application/frameworks/go_gin.md` | bind helpers, middleware coverage, GORM raw query usage |

## PHP

| Framework | File | Focus |
|-----------|------|-------|
| Laravel | `references/application/frameworks/php_laravel.md` | `Request::all()`, Eloquent mass assignment, Blade raw output, APP_KEY handling |

## Ruby

| Framework | File | Focus |
|-----------|------|-------|
| Rails | `references/application/frameworks/ruby_rails.md` | strong params, ActiveRecord injection, `html_safe`, before_action coverage |

## .NET

| Framework | File | Focus |
|-----------|------|-------|
| ASP.NET Core | `references/application/frameworks/dotnet_aspnetcore.md` | middleware order, model binding, Razor/Blazor sinks, minimal API auth |

## Rust

| Framework | File | Focus |
|-----------|------|-------|
| Axum | `references/application/frameworks/rust_axum.md` | extractors, tower layers, `serde` binding, sqlx usage |

## Swift

| Framework | File | Focus |
|-----------|------|-------|
| Vapor | `references/application/frameworks/swift_vapor.md` | `Content` binding, route groups, Leaf rendering, FileIO and URL fetchers |
