# Django Framework - Security Vulnerability Reference

## Identification Features

```bash
# Detect Django usage
grep -r "from django\|import django" --include="*.py"
grep -r "django" requirements.txt setup.py pyproject.toml Pipfile
grep -r "DJANGO_SETTINGS_MODULE" --include="*.py" --include="*.env" --include="*.sh"
grep -r "urlpatterns\|INSTALLED_APPS\|MIDDLEWARE" --include="*.py"
```

Common file patterns: `manage.py`, `settings.py`, `urls.py`, `views.py`, `models.py`, `wsgi.py`, `asgi.py`.

---

## Critical Vulnerabilities

### 1. DEBUG=True in Production

Exposes detailed error pages with source code, local variables, settings, and installed apps to any visitor.

**Dangerous:**
```python
# settings.py
DEBUG = True  # Shows full tracebacks, SQL queries, and settings to users

# Or not overridden from default
# DEBUG not set based on environment
```

**Safe:**
```python
# settings.py
import os

DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'

# Ensure DEBUG is False in production
# Set DJANGO_DEBUG=False in production environment
```

**Detection:**
```bash
grep -rn "DEBUG\s*=" --include="*.py" | grep -v "\.pyc"
grep -rn "DEBUG.*True" --include="*.py"
grep -rn "DJANGO_DEBUG" --include="*.env" --include="*.sh"
```

### 2. SECRET_KEY Hardcoded or Weak

Compromised SECRET_KEY allows session forgery, CSRF bypass, password reset token forgery, and signed cookie tampering.

**Dangerous:**
```python
# settings.py
SECRET_KEY = 'django-insecure-abc123def456'
SECRET_KEY = 'change-me-in-production'
SECRET_KEY = 'your-secret-key-here'

# Committed to version control
SECRET_KEY = 'p&l%06p^!z-0c$&u+hx#u7@r6p&!)_#1h+k=7k#y!&9o+ixek'
```

**Safe:**
```python
# settings.py
import os
from django.core.management.utils import get_random_secret_key

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = get_random_secret_key()
    else:
        raise ValueError('DJANGO_SECRET_KEY environment variable is required in production')
```

**Detection:**
```bash
grep -rn "SECRET_KEY\s*=" --include="*.py"
grep -rn "SECRET_KEY.*insecure\|SECRET_KEY.*change.me\|SECRET_KEY.*your.secret" --include="*.py"
# Check if SECRET_KEY is in version control
git log -p --all -S 'SECRET_KEY' -- '*.py'
```

### 3. SQL Injection via extra() and raw()

Using `extra()`, `raw()`, or `RawSQL` with unsanitized user input bypasses ORM protections.

**Dangerous:**
```python
from django.db.models.expressions import RawSQL

# raw() with string formatting
def search_users(request):
    query = request.GET.get('q')
    users = User.objects.raw(f"SELECT * FROM auth_user WHERE username LIKE '%{query}%'")
    return render(request, 'users.html', {'users': users})

# extra() with user input
def filter_items(request):
    order = request.GET.get('order', 'name')
    items = Item.objects.extra(order_by=[order])  # SQL injection in ORDER BY

# RawSQL annotation
def annotated_query(request):
    field = request.GET.get('field')
    items = Item.objects.annotate(val=RawSQL(f"SELECT {field} FROM items", []))
```

**Safe:**
```python
# Use ORM methods
def search_users(request):
    query = request.GET.get('q', '')
    users = User.objects.filter(username__icontains=query)
    return render(request, 'users.html', {'users': users})

# If raw SQL is needed, use parameterized queries
def search_users_raw(request):
    query = request.GET.get('q', '')
    users = User.objects.raw(
        "SELECT * FROM auth_user WHERE username LIKE %s",
        [f'%{query}%']
    )
    return render(request, 'users.html', {'users': users})

# Validate order_by against whitelist
ALLOWED_ORDER_FIELDS = ['name', '-name', 'created_at', '-created_at']
def filter_items(request):
    order = request.GET.get('order', 'name')
    if order not in ALLOWED_ORDER_FIELDS:
        order = 'name'
    items = Item.objects.order_by(order)
```

**Detection:**
```bash
grep -rn "\.raw(" --include="*.py"
grep -rn "\.extra(" --include="*.py"
grep -rn "RawSQL(" --include="*.py"
grep -rn "cursor\.execute(" --include="*.py" | grep -v "%s\|%(.*\)s"
grep -rn "connection\.cursor" --include="*.py"
```

### 4. Pickle-Based Session Backend

Pickle deserialization of tampered session data can lead to RCE if SECRET_KEY is compromised.

**Dangerous:**
```python
# settings.py
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'

# Or using cached sessions with pickle
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
# If cache backend uses pickle (default for memcached)
```

**Safe:**
```python
# settings.py - Use JSON serializer (Django default since 1.6)
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'

# Ensure session backend is database or cache with JSON
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
```

**Detection:**
```bash
grep -rn "SESSION_SERIALIZER" --include="*.py"
grep -rn "PickleSerializer" --include="*.py"
grep -rn "SESSION_ENGINE" --include="*.py"
```

### 5. Unsafe Deserialization (RCE)

Deserializing untrusted data with pickle, yaml, or marshal.

**Dangerous:**
```python
import pickle
import yaml

def load_config(request):
    data = request.body
    config = pickle.loads(data)  # RCE
    return JsonResponse(config)

def parse_yaml(request):
    data = request.body.decode()
    config = yaml.load(data)  # yaml.load without Loader is unsafe
    return JsonResponse(config)
```

**Safe:**
```python
import json
import yaml

def load_config(request):
    data = request.body
    config = json.loads(data)  # Safe: JSON cannot execute code
    return JsonResponse(config)

def parse_yaml(request):
    data = request.body.decode()
    config = yaml.safe_load(data)  # safe_load prevents code execution
    return JsonResponse(config)
```

**Detection:**
```bash
grep -rn "pickle\.loads\|pickle\.load\|cPickle" --include="*.py"
grep -rn "yaml\.load\|yaml\.unsafe_load" --include="*.py" | grep -v "safe_load"
grep -rn "marshal\.loads\|shelve\.open" --include="*.py"
```

---

## High Vulnerabilities

### 6. ORM Injection via extra() and RawSQL

Even within the ORM, certain methods accept raw SQL fragments.

**Dangerous:**
```python
# extra() with user-controlled where clause
def search(request):
    query = request.GET.get('q')
    results = Product.objects.extra(where=[f"name LIKE '%{query}%'"])

# Unvalidated field names in order_by
def list_items(request):
    sort = request.GET.get('sort')
    items = Item.objects.order_by(sort)  # Can inject: "-name); DROP TABLE--"

# values() / values_list() with user input
items = Item.objects.values(request.GET.get('field'))
```

**Safe:**
```python
# Use ORM filters
def search(request):
    query = request.GET.get('q', '')
    results = Product.objects.filter(name__icontains=query)

# Whitelist sort fields
SORT_FIELDS = {'name', '-name', 'price', '-price', 'created_at', '-created_at'}
def list_items(request):
    sort = request.GET.get('sort', 'name')
    if sort not in SORT_FIELDS:
        sort = 'name'
    items = Item.objects.order_by(sort)
```

**Detection:**
```bash
grep -rn "\.extra(\|\.raw(\|RawSQL\|cursor\.execute" --include="*.py"
grep -rn "order_by(.*request\.\|values(.*request\.\|values_list(.*request\." --include="*.py"
```

### 7. Server-Side Template Injection

If user-supplied strings are used as Django templates (uncommon but possible).

**Dangerous:**
```python
from django.template import Template, Context

def render_custom(request):
    template_string = request.POST.get('template')
    t = Template(template_string)  # User controls the template
    c = Context({'user': request.user})
    return HttpResponse(t.render(c))
```

**Safe:**
```python
# Never allow user-controlled template strings
# Use predefined templates with user data as context variables
from django.shortcuts import render

def render_custom(request):
    content = request.POST.get('content', '')
    return render(request, 'custom.html', {'content': content})
```

**Detection:**
```bash
grep -rn "Template(.*request\.\|Template(.*POST\|Template(.*GET" --include="*.py"
grep -rn "from django.template import Template" --include="*.py"
```

### 8. Mass Assignment via **request.POST

Passing all POST data directly to model creation.

**Dangerous:**
```python
def create_user(request):
    # Attacker adds: is_staff=True&is_superuser=True
    user = User.objects.create(**request.POST)
    return redirect('/dashboard')

def update_profile(request):
    user = request.user
    for key, value in request.POST.items():
        setattr(user, key, value)
    user.save()
```

**Safe:**
```python
from django import forms

class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']  # Explicit whitelist

def update_profile(request):
    form = ProfileForm(request.POST, instance=request.user)
    if form.is_valid():
        form.save()
        return redirect('/profile')
    return render(request, 'profile.html', {'form': form})

# Or explicitly pick fields
def create_user(request):
    user = User.objects.create(
        username=request.POST['username'],
        email=request.POST['email']
    )
```

**Detection:**
```bash
grep -rn "\*\*request\.POST\|\*\*request\.GET\|\*\*request\.data" --include="*.py"
grep -rn "setattr(.*request\." --include="*.py"
grep -rn "objects\.create(\*\*\|objects\.update(\*\*\|objects\.filter(\*\*.*request" --include="*.py"
```

### 9. File Upload Without Validation

**Dangerous:**
```python
def upload_file(request):
    uploaded = request.FILES['document']
    # No type validation, path traversal possible
    with open(f'/uploads/{uploaded.name}', 'wb') as f:
        for chunk in uploaded.chunks():
            f.write(chunk)
```

**Safe:**
```python
import os
import uuid
from django.core.validators import FileExtensionValidator

class Document(models.Model):
    file = models.FileField(
        upload_to='documents/',
        validators=[FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx'])],
    )

# In settings.py
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024

# Custom upload handler with validation
def upload_file(request):
    uploaded = request.FILES['document']
    allowed_types = ['application/pdf', 'image/jpeg', 'image/png']
    if uploaded.content_type not in allowed_types:
        return HttpResponseBadRequest('Invalid file type')
    if uploaded.size > 5 * 1024 * 1024:
        return HttpResponseBadRequest('File too large')
    # Use random filename
    ext = os.path.splitext(uploaded.name)[1].lower()
    filename = f"{uuid.uuid4()}{ext}"
    default_storage.save(f'documents/{filename}', uploaded)
```

**Detection:**
```bash
grep -rn "request\.FILES" --include="*.py"
grep -rn "FileField\|ImageField" --include="*.py" | grep -v "validators\|FileExtensionValidator"
grep -rn "FILE_UPLOAD_MAX_MEMORY_SIZE\|DATA_UPLOAD_MAX_MEMORY_SIZE" --include="*.py"
```

---

## Medium Vulnerabilities

### 10. XSS via |safe, mark_safe, and autoescape off

Django auto-escapes template variables by default, but these can be bypassed.

**Dangerous:**
```html
{# Template: marking user data as safe #}
<div>{{ user_comment|safe }}</div>

{% autoescape off %}
  <p>{{ user_input }}</p>
{% endautoescape %}
```

```python
from django.utils.safestring import mark_safe

def render_comment(request):
    comment = request.POST.get('comment')
    safe_comment = mark_safe(comment)  # Bypasses auto-escaping
    return render(request, 'comment.html', {'comment': safe_comment})
```

**Safe:**
```html
{# Let Django auto-escape handle it #}
<div>{{ user_comment }}</div>

{# If HTML is needed, sanitize server-side first #}
<div>{{ sanitized_comment|safe }}</div>
```

```python
import bleach

def render_comment(request):
    comment = request.POST.get('comment')
    clean = bleach.clean(comment, tags=['b', 'i', 'em', 'strong', 'a'], strip=True)
    return render(request, 'comment.html', {'comment': mark_safe(clean)})
```

**Detection:**
```bash
grep -rn "|safe" --include="*.html" --include="*.txt"
grep -rn "mark_safe(" --include="*.py"
grep -rn "autoescape off\|autoescape false" --include="*.html"
grep -rn "format_html_join\|format_html" --include="*.py"
```

### 11. CSRF Exemptions

Disabling CSRF protection on state-changing views.

**Dangerous:**
```python
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def transfer_money(request):
    # No CSRF protection on a state-changing action
    do_transfer(request.POST['amount'], request.POST['to'])
    return JsonResponse({'status': 'ok'})

# Removing CSRF middleware entirely
MIDDLEWARE = [
    # 'django.middleware.csrf.CsrfViewMiddleware',  # Commented out
]
```

**Safe:**
```python
# Keep CsrfViewMiddleware in MIDDLEWARE
# Use csrf_exempt only for truly public API endpoints with token auth
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.authentication import TokenAuthentication

@csrf_exempt  # OK because token auth replaces CSRF
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
def api_transfer(request):
    do_transfer(request.data['amount'], request.data['to'])
    return Response({'status': 'ok'})
```

**Detection:**
```bash
grep -rn "csrf_exempt" --include="*.py"
grep -rn "CsrfViewMiddleware" --include="*.py" | grep "#"
grep -rn "MIDDLEWARE" --include="*.py" | grep -v "csrf"
```

### 12. Open Redirect

**Dangerous:**
```python
from django.shortcuts import redirect

def login_view(request):
    next_url = request.GET.get('next', '/')
    if authenticate(request):
        return redirect(next_url)  # /login?next=https://evil.com
```

**Safe:**
```python
from django.utils.http import url_has_allowed_host_and_scheme

def login_view(request):
    next_url = request.GET.get('next', '/')
    if authenticate(request):
        if url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
            return redirect(next_url)
        return redirect('/')
```

**Detection:**
```bash
grep -rn "redirect(.*request\.GET\|redirect(.*request\.POST\|redirect(.*next" --include="*.py"
grep -rn "url_has_allowed_host_and_scheme\|is_safe_url" --include="*.py"
```

### 13. Clickjacking (X-Frame-Options)

**Dangerous:**
```python
# Missing XFrameOptionsMiddleware
MIDDLEWARE = [
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Or exempt on sensitive pages
from django.views.decorators.clickjacking import xframe_options_exempt

@xframe_options_exempt
def payment_page(request):
    return render(request, 'payment.html')
```

**Safe:**
```python
# settings.py
MIDDLEWARE = [
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
X_FRAME_OPTIONS = 'DENY'  # or 'SAMEORIGIN'
```

**Detection:**
```bash
grep -rn "XFrameOptionsMiddleware" --include="*.py"
grep -rn "X_FRAME_OPTIONS" --include="*.py"
grep -rn "xframe_options_exempt\|xframe_options_sameorigin" --include="*.py"
```

### 14. Admin Panel Exposed

**Dangerous:**
```python
# urls.py - default admin URL
urlpatterns = [
    path('admin/', admin.site.urls),  # Easy to find
]
# No IP restriction or additional authentication
```

**Safe:**
```python
# urls.py - custom admin URL
urlpatterns = [
    path('manage-kx7q2p/', admin.site.urls),  # Obscure URL
]

# Additional protection via middleware or decorator
# Restrict admin to specific IPs or require VPN
# Use django-admin-honeypot for the default /admin/ URL

# settings.py
ADMIN_ENABLED = os.environ.get('ADMIN_ENABLED', 'false') == 'true'
```

**Detection:**
```bash
grep -rn "admin\.site\.urls\|admin/" --include="*.py" | grep "urlpatterns\|path(\|url("
grep -rn "admin-honeypot\|AdminHoneypot" --include="*.py" package.json
```

---

## Security Settings Audit

### 15. Critical Django Settings

**Dangerous:**
```python
# settings.py - insecure configuration
DEBUG = True
SECRET_KEY = 'hardcoded-key'
ALLOWED_HOSTS = ['*']
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False
SECURE_HSTS_SECONDS = 0
```

**Safe:**
```python
# settings.py - production secure configuration
import os

DEBUG = False
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
ALLOWED_HOSTS = ['myapp.com', 'www.myapp.com']

# HTTPS / TLS
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Session security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 3600  # 1 hour

# CSRF
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Content Security Policy (django-csp)
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
```

**Detection:**
```bash
grep -rn "ALLOWED_HOSTS\|SECURE_SSL_REDIRECT\|SESSION_COOKIE_SECURE\|CSRF_COOKIE_SECURE" --include="*.py"
grep -rn "SECURE_HSTS_SECONDS\|SECURE_BROWSER_XSS_FILTER\|SECURE_CONTENT_TYPE_NOSNIFF" --include="*.py"
grep -rn "SESSION_COOKIE_HTTPONLY\|SESSION_COOKIE_SAMESITE" --include="*.py"

# Django's built-in security check
python manage.py check --deploy
```

---

## Detection Commands

```bash
# Full Django security scan
echo "=== Debug Mode ==="
grep -rn "DEBUG\s*=\s*True" --include="*.py"

echo "=== Secret Key ==="
grep -rn "SECRET_KEY\s*=" --include="*.py" | grep -v "os\.environ\|env("

echo "=== SQL Injection ==="
grep -rn "\.raw(\|\.extra(\|RawSQL\|cursor\.execute" --include="*.py"

echo "=== Deserialization ==="
grep -rn "pickle\.\|yaml\.load\|marshal\." --include="*.py"

echo "=== XSS ==="
grep -rn "|safe" --include="*.html"
grep -rn "mark_safe(" --include="*.py"
grep -rn "autoescape off" --include="*.html"

echo "=== CSRF ==="
grep -rn "csrf_exempt" --include="*.py"

echo "=== Mass Assignment ==="
grep -rn "\*\*request\.POST\|\*\*request\.data" --include="*.py"

echo "=== Open Redirect ==="
grep -rn "redirect(.*request\." --include="*.py"

echo "=== File Uploads ==="
grep -rn "request\.FILES" --include="*.py"

echo "=== Security Settings ==="
grep -rn "ALLOWED_HOSTS\|SECURE_SSL_REDIRECT\|SESSION_COOKIE_SECURE" --include="*.py"
grep -rn "CSRF_COOKIE_SECURE\|SECURE_HSTS" --include="*.py"

echo "=== Admin ==="
grep -rn "admin\.site\.urls" --include="*.py"

echo "=== Django Security Check ==="
# python manage.py check --deploy
```

---

## Audit Checklist

- [ ] `DEBUG = False` in production
- [ ] `SECRET_KEY` is strong, from environment variable, not in version control
- [ ] `ALLOWED_HOSTS` is restricted to actual domain names (no `*`)
- [ ] No `.raw()` or `.extra()` with user input; all SQL parameterized
- [ ] No `pickle.loads()` or `yaml.load()` on user-controlled data
- [ ] `SESSION_SERIALIZER` is `JSONSerializer` (not Pickle)
- [ ] `|safe` and `mark_safe()` only used on sanitized content
- [ ] `{% autoescape off %}` not used with user data
- [ ] `csrf_exempt` used sparingly and only with alternative auth
- [ ] No `**request.POST` or `**request.data` in model create/update
- [ ] File uploads validate type, size; use Django `FileField` validators
- [ ] `SECURE_SSL_REDIRECT = True`
- [ ] `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`
- [ ] `CSRF_COOKIE_SECURE = True`
- [ ] `SECURE_HSTS_SECONDS > 0` with `INCLUDE_SUBDOMAINS`
- [ ] `XFrameOptionsMiddleware` active, `X_FRAME_OPTIONS = 'DENY'`
- [ ] Admin URL is non-default and access-restricted
- [ ] `python manage.py check --deploy` passes with no warnings
- [ ] Open redirects use `url_has_allowed_host_and_scheme()`
