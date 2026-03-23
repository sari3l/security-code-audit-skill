# XSS in Template Engines

Every major template engine has constructs that bypass auto-escaping. This reference covers the dangerous vs safe patterns for each.

---

## Jinja2 (Python / Flask)

**Default behavior:** Auto-escaping is ON for `.html`, `.htm`, `.xml`, `.xhtml` extensions in Flask.

### Dangerous Patterns

```python
# 1. The |safe filter - marks string as safe (no escaping)
{{ user_input|safe }}

# 2. Disabling autoescape for a block
{% autoescape false %}
  {{ user_input }}  {# NOT escaped #}
{% endautoescape %}

# 3. Markup() in Python code marks strings as safe
from markupsafe import Markup
# VULNERABLE: wrapping user input in Markup
return render_template('page.html', content=Markup(user_input))

# 4. Passing through Markup concatenation
safe_html = Markup('<div>') + Markup(user_input) + Markup('</div>')
# Each Markup() call individually trusts its argument
```

### Safe Patterns

```python
# Auto-escaped by default in .html templates
{{ user_input }}

# Explicit escaping
{{ user_input|e }}

# Markup.escape() for Python-side escaping
from markupsafe import Markup
safe = Markup.escape(user_input)
```

### Detection

```bash
grep -rn '|safe\b' --include='*.html' --include='*.jinja' --include='*.jinja2' --include='*.j2'
grep -rn 'autoescape false\|autoescape off' --include='*.html' --include='*.jinja' --include='*.jinja2' --include='*.j2'
grep -rn 'Markup(' --include='*.py' | grep -v 'Markup\.escape\|Markup()'
```

---

## Django Templates

**Default behavior:** Auto-escaping is ON by default.

### Dangerous Patterns

```html
{# 1. The |safe filter #}
{{ user_input|safe }}

{# 2. Disabling autoescape for a block #}
{% autoescape off %}
  {{ user_input }}
{% endautoescape %}
```

```python
# 3. mark_safe() in Python code
from django.utils.safestring import mark_safe
# VULNERABLE
return mark_safe(f"<span>{user_input}</span>")

# 4. format_html used incorrectly
from django.utils.html import format_html
# SAFE - arguments are escaped
format_html('<span class="{}">{}</span>', cls, user_input)
# VULNERABLE - pre-concatenated string
format_html(f'<span>{user_input}</span>')
```

### Safe Patterns

```html
{# Auto-escaped by default #}
{{ user_input }}

{# Explicit escape #}
{{ user_input|escape }}

{# Force escape even if marked safe #}
{{ user_input|force_escape }}
```

### Detection

```bash
grep -rn '|safe\b' --include='*.html' --include='*.txt' --include='*.django'
grep -rn 'autoescape off' --include='*.html' --include='*.django'
grep -rn 'mark_safe(' --include='*.py'
grep -rn 'format_html.*f"' --include='*.py'
grep -rn 'format_html.*\.format(' --include='*.py'
```

---

## EJS (Node.js / Express)

**Default behavior:** `<%= %>` escapes HTML. `<%- %>` does NOT.

### Dangerous Patterns

```html
<%# UNESCAPED output - XSS if user-controlled %>
<%- user_input %>
<%- include('partial', { content: user_input }) %>
```

### Safe Patterns

```html
<%# ESCAPED output %>
<%= user_input %>
```

### Detection

```bash
grep -rn '<%- ' --include='*.ejs'
```

---

## Handlebars / Mustache

**Default behavior:** `{{ }}` double-stache escapes. `{{{ }}}` triple-stache does NOT.

### Dangerous Patterns

```html
{{! UNESCAPED - triple braces }}
{{{ user_input }}}

{{! Also unescaped with SafeString in helpers }}
```

```javascript
// VULNERABLE: returning SafeString with user input
Handlebars.registerHelper('rawContent', function(text) {
  return new Handlebars.SafeString(text); // Bypasses escaping
});
```

### Safe Patterns

```html
{{! Escaped by default }}
{{ user_input }}
```

### Detection

```bash
grep -rn '{{{' --include='*.hbs' --include='*.handlebars' --include='*.mustache'
grep -rn 'SafeString(' --include='*.js' --include='*.ts'
```

---

## Pug / Jade (Node.js)

**Default behavior:** `#{}` interpolation escapes. `!{}` does NOT.

### Dangerous Patterns

```pug
//- UNESCAPED interpolation
p !{user_input}

//- UNESCAPED tag content
p!= user_input

//- UNESCAPED attribute (less common)
div(class!= user_input)
```

### Safe Patterns

```pug
//- Escaped interpolation
p #{user_input}

//- Escaped tag content
p= user_input
```

### Detection

```bash
grep -rn '!{' --include='*.pug' --include='*.jade'
grep -rn '!=' --include='*.pug' --include='*.jade' | grep -v '!==' | grep -v '<!--'
```

---

## React / JSX

**Default behavior:** JSX expressions `{}` auto-escape strings. `dangerouslySetInnerHTML` does NOT.

### Dangerous Patterns

```jsx
// 1. dangerouslySetInnerHTML - injects raw HTML
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// 2. Creating elements with user-controlled HTML
const element = React.createElement('div', {
  dangerouslySetInnerHTML: { __html: userInput }
});

// 3. href with javascript: protocol
<a href={userInput}>Click</a>
// If userInput = "javascript:alert(1)" => XSS on click

// 4. Dynamic component rendering with user input
const Component = userControlledComponentName;
<Component />  // Could render unexpected component
```

### Safe Patterns

```jsx
// Auto-escaped by default
<div>{userInput}</div>

// For rich text, use a sanitizer
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(richContent) }} />

// Validate URLs
const isValidUrl = (url) => {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch { return false; }
};
```

### Detection

```bash
grep -rn 'dangerouslySetInnerHTML' --include='*.jsx' --include='*.tsx' --include='*.js' --include='*.ts'
grep -rn '__html' --include='*.jsx' --include='*.tsx' --include='*.js' --include='*.ts'
```

---

## Vue.js

**Default behavior:** `{{ }}` double-mustache escapes. `v-html` directive does NOT.

### Dangerous Patterns

```html
<!-- v-html renders raw HTML -->
<div v-html="userInput"></div>

<!-- Dynamic component with user input -->
<component :is="userControlledComponent"></component>

<!-- User-controlled href -->
<a :href="userInput">Link</a>
<!-- javascript: protocol is blocked in Vue 3 for :href but not in Vue 2 -->
```

```javascript
// VULNERABLE: Compile-time template injection (SSR)
new Vue({
  template: `<div>${userInput}</div>`  // Template injection
});
```

### Safe Patterns

```html
<!-- Escaped by default -->
<div>{{ userInput }}</div>

<!-- For rich text, sanitize first -->
<div v-html="sanitizedContent"></div>
```

```javascript
// In setup/computed:
import DOMPurify from 'dompurify';
const sanitizedContent = computed(() => DOMPurify.sanitize(rawHtml.value));
```

### Detection

```bash
grep -rn 'v-html' --include='*.vue' --include='*.html'
grep -rn 'template:.*\$\{' --include='*.js' --include='*.ts' --include='*.vue'
```

---

## Angular

**Default behavior:** Interpolation `{{ }}` escapes. `[innerHTML]` sanitizes (but can be bypassed).

### Dangerous Patterns

```typescript
// 1. bypassSecurityTrust* methods disable Angular's sanitizer
import { DomSanitizer } from '@angular/platform-browser';

constructor(private sanitizer: DomSanitizer) {}

// VULNERABLE: marks user input as trusted
this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);
this.trustedUrl = this.sanitizer.bypassSecurityTrustUrl(userInput);
this.trustedResourceUrl = this.sanitizer.bypassSecurityTrustResourceUrl(userInput);
this.trustedScript = this.sanitizer.bypassSecurityTrustScript(userInput);
this.trustedStyle = this.sanitizer.bypassSecurityTrustStyle(userInput);
```

```html
<!-- 2. [innerHTML] with bypassed sanitizer -->
<div [innerHTML]="trustedHtml"></div>

<!-- 3. [innerHTML] is sanitized by Angular, but the sanitizer has known bypasses
     in older versions -->
<div [innerHTML]="userInput"></div>
```

### Safe Patterns

```html
<!-- Interpolation is always escaped -->
{{ userInput }}

<!-- [innerHTML] with Angular's built-in sanitizer (reasonable for most cases) -->
<div [innerHTML]="userInput"></div>
<!-- Angular strips dangerous tags/attributes automatically -->
```

### Detection

```bash
grep -rn 'bypassSecurityTrust' --include='*.ts' --include='*.js'
grep -rn '\[innerHTML\]' --include='*.html' --include='*.ts' --include='*.component.html'
grep -rn 'DomSanitizer' --include='*.ts'
```

---

## Blade (Laravel / PHP)

**Default behavior:** `{{ }}` escapes. `{!! !!}` does NOT.

### Dangerous Patterns

```php
{{-- UNESCAPED output --}}
{!! $userInput !!}

{{-- Unescaped in older Laravel or misconfigured --}}
<?php echo $userInput; ?>
```

### Safe Patterns

```php
{{-- Escaped by default --}}
{{ $userInput }}

{{-- Explicit escaping --}}
{{ e($userInput) }}
```

### Detection

```bash
grep -rn '{!!' --include='*.blade.php'
grep -rn 'echo \$' --include='*.blade.php' --include='*.php' | grep -v 'htmlspecialchars\|e(\|htmlentities'
```

---

## ERB (Ruby on Rails)

**Default behavior:** `<%= %>` escapes in Rails 3+ (with `html_safe` system). `<%== %>` does NOT.

### Dangerous Patterns

```erb
<%# UNESCAPED output %>
<%== user_input %>

<%# raw() helper - bypasses escaping %>
<%= raw(user_input) %>

<%# html_safe marks string as safe %>
<%= user_input.html_safe %>
```

```ruby
# In Ruby code - marking user input as safe
content = user_input.html_safe  # VULNERABLE
content = raw(user_input)       # VULNERABLE
```

### Safe Patterns

```erb
<%# Escaped by default in Rails 3+ %>
<%= user_input %>

<%# Explicit sanitization %>
<%= sanitize(user_input) %>
<%= sanitize(user_input, tags: %w[b i em strong], attributes: %w[class]) %>
```

### Detection

```bash
grep -rn '<%==' --include='*.erb' --include='*.html.erb'
grep -rn '\.html_safe' --include='*.rb' --include='*.erb'
grep -rn '\braw(' --include='*.rb' --include='*.erb'
```

---

## Thymeleaf (Java / Spring)

**Default behavior:** `th:text` escapes. `th:utext` does NOT (unescaped text).

### Dangerous Patterns

```html
<!-- UNESCAPED output -->
<span th:utext="${userInput}"></span>

<!-- Inline unescaped -->
<p>[[${userInput}]]</p>  <!-- th:text equivalent, escaped -->
<p>[(${userInput})]</p>  <!-- th:utext equivalent, UNESCAPED -->
```

### Safe Patterns

```html
<!-- Escaped by default -->
<span th:text="${userInput}"></span>

<!-- Inline escaped -->
<p>[[${userInput}]]</p>
```

### Detection

```bash
grep -rn 'th:utext' --include='*.html' --include='*.xml'
grep -rn '\[\(' --include='*.html' | grep '\${'
```

---

## Comprehensive Detection Script

Run this to scan for unescaped output across all template engines:

```bash
echo "=== Jinja2 / Flask ==="
grep -rn '|safe\b' --include='*.html' --include='*.jinja*' --include='*.j2'
grep -rn 'autoescape false' --include='*.html' --include='*.jinja*' --include='*.j2'
grep -rn 'Markup(' --include='*.py' | grep -v 'Markup\.escape\|Markup()'

echo "=== Django ==="
grep -rn '|safe\b' --include='*.html' | grep -v 'jinja\|jinja2'
grep -rn 'mark_safe(' --include='*.py'
grep -rn 'autoescape off' --include='*.html'

echo "=== EJS ==="
grep -rn '<%- ' --include='*.ejs'

echo "=== Handlebars ==="
grep -rn '{{{' --include='*.hbs' --include='*.handlebars'
grep -rn 'SafeString(' --include='*.js' --include='*.ts'

echo "=== Pug ==="
grep -rn '!{' --include='*.pug' --include='*.jade'

echo "=== React ==="
grep -rn 'dangerouslySetInnerHTML' --include='*.jsx' --include='*.tsx' --include='*.js' --include='*.ts'

echo "=== Vue ==="
grep -rn 'v-html' --include='*.vue'

echo "=== Angular ==="
grep -rn 'bypassSecurityTrust' --include='*.ts'

echo "=== Blade ==="
grep -rn '{!!' --include='*.blade.php'

echo "=== ERB ==="
grep -rn '<%==' --include='*.erb'
grep -rn '\.html_safe' --include='*.rb' --include='*.erb'
grep -rn '\braw(' --include='*.rb' --include='*.erb'

echo "=== Thymeleaf ==="
grep -rn 'th:utext' --include='*.html'
```

---

## Quick Reference Table

| Engine | Escaped (Safe) | Unescaped (Dangerous) |
|---|---|---|
| **Jinja2** | `{{ x }}` | `{{ x\|safe }}`, `{% autoescape false %}` |
| **Django** | `{{ x }}` | `{{ x\|safe }}`, `{% autoescape off %}`, `mark_safe()` |
| **EJS** | `<%= x %>` | `<%- x %>` |
| **Handlebars** | `{{ x }}` | `{{{ x }}}`, `SafeString()` |
| **Pug** | `#{x}`, `= x` | `!{x}`, `!= x` |
| **React** | `{x}` | `dangerouslySetInnerHTML` |
| **Vue** | `{{ x }}` | `v-html` |
| **Angular** | `{{ x }}` | `bypassSecurityTrust*()` |
| **Blade** | `{{ $x }}` | `{!! $x !!}` |
| **ERB** | `<%= x %>` | `<%== x %>`, `.html_safe`, `raw()` |
| **Thymeleaf** | `th:text` | `th:utext` |
