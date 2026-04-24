# ASP.NET Core Security Reference

## Identification Features

```bash
find . -name "*.csproj" -exec grep -l "Microsoft.NET.Sdk.Web" {} \;
grep -r "WebApplication\.CreateBuilder\|UseAuthentication\|MapControllers" --include="*.cs"
grep -r "\[ApiController\]\|\[Authorize\]" --include="*.cs"
```

Common file patterns: `Program.cs`, `Controllers/`, `Pages/`, `Views/`, `appsettings*.json`, `wwwroot/`.

---

## High-Risk Framework Surfaces

### 1. Middleware Ordering

- `UseAuthorization()` before `UseAuthentication()`
- mapping endpoints before auth middleware
- relying on `[Authorize]` while minimal APIs remain unprotected

### 2. Model Binding Overreach

- entities bound directly from `[FromBody]`
- `TryUpdateModelAsync` or automapper copying privileged fields
- JSON Patch endpoints with insufficient path restrictions

### 3. Rendering and Client Sinks

- `Html.Raw` in Razor
- `MarkupString` or raw HTML in Blazor
- file upload and static file exposure under `wwwroot`

### 4. Framework Diagnostics

- Swagger, developer exception page, health checks, or debug endpoints exposed broadly

---

## Detection Commands

```bash
grep -rn 'UseAuthentication|UseAuthorization|MapControllers|MapGet|MapPost|RequireAuthorization' --include="*.cs"
grep -rn '\\[FromBody\\].*Entity|TryUpdateModelAsync|JsonPatchDocument|_mapper.Map' --include="*.cs"
grep -rn 'Html\\.Raw|MarkupString|UseDeveloperExceptionPage|AddSwaggerGen|MapHealthChecks' --include="*.cs" --include="*.cshtml" --include="*.razor"
grep -rn 'UseStaticFiles|wwwroot|IFormFile|FileStream' --include="*.cs"
```

---

## Audit Questions

- Do MVC, minimal API, SignalR, and Razor paths share the same auth guarantees?
- Are DTOs distinct from entities for write operations?
- Are raw HTML helpers confined to trusted content?
- Are diagnostics and API docs restricted outside development?
