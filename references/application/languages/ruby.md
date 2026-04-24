# Ruby / Rails Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers Rails, Sinatra, Hanami, background jobs, and common Rack middleware patterns.

---

## Language-Specific Hotspots

- ActiveRecord string interpolation and `Arel.sql` bypasses
- Authorization gaps hidden behind `before_action :authenticate_user!`
- Strong Parameters mistakes: `permit!`, nested attributes, `accepts_nested_attributes_for`
- Templating and meta-programming footguns: `html_safe`, `raw`, `ERB.new`, `send`, `constantize`

---

## C1: Injection

### Key Questions
- Are SQL fragments built with interpolation, `find_by_sql`, `order`, or `Arel.sql`?
- Can user input reach `system`, backticks, `%x{}`, `Open3`, or `IO.popen`?
- Is user input used in `send`, `public_send`, `constantize`, `ERB.new`, or `instance_eval`?
- Are YAML or Marshal payloads flowing from untrusted sources?

### Dangerous Patterns

```ruby
# SQL injection
User.where("email = '#{params[:email]}'")
User.order(params[:sort])
ActiveRecord::Base.connection.execute("DELETE FROM users WHERE id = #{params[:id]}")

# Method / code injection
public_send(params[:action])
klass = params[:type].constantize
ERB.new(params[:template]).result(binding)

# Command injection
system("tar -xf #{params[:archive]}")
output = `ping -c 1 #{params[:host]}`
```

### Safe Alternatives

```ruby
User.where(email: params[:email])

sort = %w[name created_at].include?(params[:sort]) ? params[:sort] : "created_at"
User.order(sort => :desc)

raise ArgumentError unless ALLOWED_ACTIONS.include?(params[:action])
public_send(params[:action])

Open3.capture3("ping", "-c", "1", validated_host)
```

### Grep Detection Patterns

```bash
grep -rn 'where\\(".*#\\{|find_by_sql|execute\\(|Arel\\.sql|order\\(params' --include="*.rb"
grep -rn 'system\\(|exec\\(|`|%x\\{|Open3|IO\\.popen' --include="*.rb"
grep -rn 'send\\(|public_send\\(|constantize|safe_constantize|ERB\\.new|eval|instance_eval|class_eval' --include="*.rb"
grep -rn 'Marshal\\.load|YAML\\.load|Psych\\.load' --include="*.rb"
```

---

## C2: Authentication

### Key Questions
- Are Devise or custom auth filters applied consistently?
- Is `reset_session` used after login and privilege elevation?
- Are password reset, magic link, and invitation flows short-lived and single-use?
- Are API tokens, JWTs, and signed cookies validated with pinned algorithms and strong secrets?

### Commonly Missed
- `skip_before_action :authenticate_user!` on sensitive actions
- `secret_key_base` committed or shared across environments
- Plaintext API tokens stored and compared without hashing
- MFA / OTP verification endpoints missing rate limits

### Detection

```bash
grep -rn 'authenticate_user!|require_login|skip_before_action' --include="*.rb"
grep -rn 'reset_session|session\\[:user_id\\]|signed\\[:|encrypted\\[:' --include="*.rb"
grep -rn 'JWT|jsonwebtoken|secret_key_base|magic|reset_password|otp' --include="*.rb" --include="*.yml" --include=".env*"
grep -rn 'has_secure_password|BCrypt|Digest::(MD5|SHA1|SHA256)' --include="*.rb"
```

---

## C3: Authorization

### Key Questions
- Are objects fetched through `current_user` / tenant scope rather than `Model.find(params[:id])`?
- Do Pundit or CanCanCan policies cover `show`, `update`, `destroy`, and bulk actions consistently?
- Is `after_action :verify_authorized` or equivalent enabled to catch missed checks?
- Are admin dashboards, Sidekiq Web, and internal tools protected separately from app auth?

### Detection

```bash
grep -rn 'find\\(params\\[:id\\]\\)|find_by\\(id: params\\[:id\\]\\)' --include="*.rb"
grep -rn 'authorize|policy_scope|load_and_authorize_resource|can\\?|cannot\\?' --include="*.rb"
grep -rn 'mount Sidekiq::Web|namespace :admin|admin\\?' --include="*.rb" config/routes.rb
```

---

## C4: Mass Assignment

### Key Questions
- Are controllers using Strong Parameters narrowly, or is `permit!` present?
- Can nested attributes change ownership, role, billing, or security-sensitive associations?
- Do service objects call `update(params)` or `assign_attributes` on unfiltered hashes?
- Are JSON APIs merging arbitrary payloads into models or serializers?

### Dangerous Patterns

```ruby
User.create!(params[:user])
@account.update!(params.require(:account).permit!)
@user.assign_attributes(params[:user].to_h)

accepts_nested_attributes_for :memberships
# attacker submits memberships_attributes with admin flags
```

### Detection

```bash
grep -rn 'permit!|assign_attributes|update!\\(|update\\(|create!\\(|create\\(' --include="*.rb"
grep -rn 'accepts_nested_attributes_for|fields_for' --include="*.rb"
grep -rn 'role|admin|owner_id|tenant_id|credit_limit|balance' --include="*.rb"
```

---

## C5: Data Exposure

### Key Questions
- Do serializers or `as_json` implementations leak tokens, internal IDs, or signed blob URLs?
- Are debug endpoints, exceptions, or ActiveStorage public URLs exposing sensitive content?
- Are logs filtered for secrets and PII?
- Is `to_json` or `inspect` called on full model objects in controllers or jobs?

### Detection

```bash
grep -rn 'as_json|to_json|serializable_hash|render json:' --include="*.rb"
grep -rn 'consider_all_requests_local|debug_exception_response_format|show_exceptions' --include="*.rb" config
grep -rn 'filter_parameters|password|token|secret|authorization' config app --include="*.rb"
```

---

## C6: Security Misconfiguration

### Key Questions
- Is `config.force_ssl` enabled in production?
- Are CORS, CSRF, host authorization, and cookie settings restrictive?
- Are internal UIs like `/rails/mailers`, `/rails/info`, or job consoles reachable?
- Are production secrets sourced from credentials or env, not committed YAML?

### Detection

```bash
grep -rn 'force_ssl|forgery_protection_origin_check|protect_from_forgery|rack-cors|config\\.hosts' config app --include="*.rb"
grep -rn 'allow do|origins "\\*"|credentials: true' config --include="*.rb"
grep -rn 'credentials.yml|master.key|secrets.yml|database.yml' .
```

---

## C7: XSS

### Key Questions
- Are templates using `raw`, `html_safe`, or unsafe helpers on user-controlled data?
- Is content sanitized appropriately for HTML, Markdown, and rich-text editors?
- Are values embedded into JavaScript or data attributes safely?
- Can uploaded SVG, HTML, or rendered markdown execute script?

### Dangerous Patterns

```ruby
raw(params[:content])
params[:content].html_safe
render inline: params[:template]
```

### Detection

```bash
grep -rn 'html_safe|raw\\(|safe_join|render inline:|sanitize\\(' --include="*.rb" --include="*.erb" --include="*.haml" --include="*.slim"
grep -rn '<%= raw|!=|!=\\s' app/views --include="*.erb" --include="*.haml" --include="*.slim"
```

---

## C8: Dependencies

### Review Checklist
- Run `bundle audit` and `brakeman`.
- Review gems providing auth, file upload, markdown rendering, background jobs, and serialization.
- Flag EOL Ruby and Rails versions even when no single sink is obvious.
- Check vendored JavaScript and admin consoles, not just Gem dependencies.

### Detection

```bash
bundle audit
brakeman -q
grep -rn 'ruby "|gem "rails"|gem "devise"|gem "sidekiq"|gem "carrierwave"|gem "paperclip"' Gemfile Gemfile.lock
```

---

## C9: Cryptography

### Key Questions
- Are secrets generated with `SecureRandom`, not `rand`?
- Are passwords hashed with `has_secure_password` / bcrypt, not `Digest::*`?
- Are `MessageEncryptor` and cookie secrets rotated and environment-specific?
- Are comparisons constant-time for secrets and webhook signatures?

### Detection

```bash
grep -rn 'Digest::(MD5|SHA1|SHA256)|OpenSSL::Cipher|SecureRandom|rand\\(' --include="*.rb"
grep -rn 'secure_compare|fixed_length_secure_compare|MessageEncryptor|MessageVerifier' --include="*.rb"
```

---

## C10: SSRF

### Key Questions
- Can user-provided URLs reach `Net::HTTP`, `URI.open`, `HTTParty`, `Faraday`, or `RestClient`?
- Are redirects, DNS rebinding, localhost, RFC1918, and metadata IPs blocked after resolution?
- Are webhook and image-fetch features revalidated on every request?
- Are dangerous schemes and Unix-socket adapters disabled?

### Detection

```bash
grep -rn 'Net::HTTP|URI\\.open|open\\(|HTTParty|Faraday|RestClient' --include="*.rb"
grep -rn 'redirect|follow_redirects|allow_localhost|169\\.254\\.169\\.254|127\\.0\\.0\\.1|::1' --include="*.rb"
```

---

## C11: Logging & Monitoring

### Key Questions
- Are secrets filtered from Rails logs and background-job payloads?
- Can user input forge log lines or high-cardinality log fields?
- Are auth failures, privilege changes, and destructive admin actions audited?
- Do exception reporters capture request bodies or headers containing tokens?

### Detection

```bash
grep -rn 'Rails\\.logger|logger\\.|Honeybadger|Sentry|Bugsnag|Lograge' --include="*.rb"
grep -rn 'filter_parameters|authorization|cookie|token|password' --include="*.rb"
```

---

## C12: Infrastructure & Deployment

### Key Questions
- Are uploads and generated files stored outside public execution paths?
- Are Sidekiq, ActionCable, and internal dashboards isolated and authenticated?
- Do Docker, CI, and release scripts leak credentials or development settings?
- Are Redis, Postgres, and object-storage endpoints protected from broad network exposure?

### Detection

```bash
find . -name "Dockerfile" -o -name "docker-compose.yml" -o -name ".github" -o -name "Procfile"
grep -rn 'USER root|RAILS_ENV=development|master.key|bundle exec rails s|sidekiq' --include="Dockerfile" --include="*.yml" --include="Procfile"
```
