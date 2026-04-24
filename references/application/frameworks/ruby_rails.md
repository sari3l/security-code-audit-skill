# Ruby on Rails Security Reference

## Identification Features

```bash
grep -r 'gem "rails"' Gemfile Gemfile.lock
grep -r "ApplicationController\|ActionController::Base" --include="*.rb"
test -f config/routes.rb && echo rails
```

Common file patterns: `app/controllers/`, `app/models/`, `app/views/`, `config/routes.rb`, `config/environments/`.

---

## High-Risk Framework Surfaces

### 1. Strong Parameters Failures

- `permit!`
- over-broad `permit` lists including role or admin flags
- nested attributes writing into privileged associations

### 2. ActiveRecord Escape Hatches

- interpolated `where`, `order`, `pluck`, `select`, `find_by_sql`
- `Arel.sql` used as a bypass without allowlists

### 3. View and Rich-Text Trust

- `html_safe`, `raw`, `render inline:`
- ActionText, markdown, or WYSIWYG content replayed to privileged viewers

### 4. Filter and Policy Coverage

- missing `before_action :authenticate_user!`
- controller actions missing `authorize`
- `skip_before_action` punching holes through inherited security

---

## Dangerous Patterns

```ruby
params.require(:user).permit!
User.where("name = '#{params[:name]}'")
raw(params[:content])
```

---

## Detection Commands

```bash
grep -rn 'permit!|to_unsafe_h|to_unsafe_hash' --include="*.rb"
grep -rn 'where\\(".*#\\{|find_by_sql|order\\(params|Arel\\.sql|pluck\\(params' --include="*.rb"
grep -rn 'html_safe|raw\\(|render inline:' --include="*.rb" --include="*.erb" --include="*.haml" --include="*.slim"
grep -rn 'authenticate_user!|authorize|policy_scope|skip_before_action' --include="*.rb"
```

---

## Audit Questions

- Are strong parameters truly narrow on create and update flows?
- Do policies cover read, update, delete, export, and batch actions consistently?
- Can untrusted content reach admins or support users through stored rendering paths?
- Are controller-wide protections undone on specific actions?
