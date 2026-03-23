# Laravel Security Reference

## Identification Features

```bash
grep -r '"laravel/framework"' composer.json composer.lock
grep -r "Illuminate\\\|Route::\|Schema::" --include="*.php"
test -f artisan && echo laravel
```

Common file patterns: `app/Http/Controllers/`, `routes/web.php`, `routes/api.php`, `app/Models/`, `resources/views/`.

---

## High-Risk Framework Surfaces

### 1. Request Binding and Mass Assignment

- `$request->all()` passed to `create`, `update`, `fill`
- `$guarded = []` or over-broad `$fillable`
- FormRequests present for some flows but not all

### 2. Query Builder Escape Hatches

- `whereRaw`, `orderByRaw`, `DB::statement`, `selectRaw`
- dynamic sort, column, and table values from request input

### 3. Blade and Trusted HTML

- `{!! !!}` on user-controlled data
- markdown or rich-text content marked trusted without sanitization

### 4. Framework Secrets and Debug

- `APP_KEY` exposure
- `APP_DEBUG=true`
- Laravel Telescope / Debugbar exposed in non-dev environments

---

## Dangerous Patterns

```php
User::create($request->all());

class User extends Model {
    protected $guarded = [];
}

$users = User::whereRaw("name = '$name'")->get();
```

---

## Detection Commands

```bash
grep -rn '\\$request->all\\(|create\\(\\$request|update\\(\\$request|fill\\(\\$request' --include="*.php"
grep -rn '\\$guarded\\s*=\\s*\\[\\]|\\$fillable' --include="*.php"
grep -rn 'whereRaw\\(|orderByRaw\\(|selectRaw\\(|DB::statement\\(' --include="*.php"
grep -rn '{!!|APP_DEBUG|APP_KEY|Telescope|Debugbar' --include="*.php" --include=".env*"
```

---

## Audit Questions

- Are safe DTO / request objects used, or are raw request bags pushed into models?
- Are raw query helpers justified and parameterized?
- Is debug tooling reachable outside local development?
- Are Blade raw output helpers used only after explicit sanitization?
