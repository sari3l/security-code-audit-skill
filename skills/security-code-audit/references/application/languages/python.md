# Python Security Checklist

Language-specific security checklist organized by C1-C12 categories. Each section provides key questions, dangerous patterns, safe alternatives, and grep detection patterns.

---

## C1: Injection

### Key Questions
- Are any SQL queries built with string formatting or concatenation?
- Does any code call `os.system`, `subprocess` with `shell=True`, or `eval`/`exec`?
- Is `pickle`, `yaml.load`, or `marshal` used on untrusted data?
- Are ORM raw query methods used with user input?

### Commonly Missed
- f-string SQL: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
- `subprocess.run` with `shell=True` and user-controlled arguments
- `yaml.load(data)` without `Loader=SafeLoader` (allows arbitrary code execution)
- Django `extra()`, `raw()`, `RawSQL()` with interpolated strings
- SQLAlchemy `text()` with string formatting
- `__import__()` with user-controlled module names

### Dangerous Patterns

```python
# SQL injection via f-string
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# SQL injection via % formatting
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)

# SQL injection via .format()
cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))

# Django ORM raw query injection
User.objects.raw("SELECT * FROM auth_user WHERE id = %s" % user_id)
User.objects.extra(where=["name = '%s'" % name])

# SQLAlchemy text injection
db.session.execute(text(f"SELECT * FROM users WHERE id = {uid}"))

# OS command injection
os.system("ping " + user_input)
subprocess.call(user_input, shell=True)
subprocess.Popen(f"grep {pattern} /var/log/app.log", shell=True)

# Code injection
eval(user_input)
exec(user_input)
compile(user_input, '<string>', 'exec')

# Deserialization
pickle.loads(untrusted_data)
yaml.load(untrusted_data)  # missing Loader=SafeLoader
marshal.loads(untrusted_data)
```

### Safe Alternatives

```python
# Parameterized SQL
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))

# Django ORM
User.objects.filter(name=name)
User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])

# SQLAlchemy parameterized
db.session.execute(text("SELECT * FROM users WHERE id = :uid"), {"uid": uid})

# Safe subprocess
subprocess.run(["ping", "-c", "1", user_input], shell=False)

# Safe YAML
yaml.load(data, Loader=yaml.SafeLoader)
yaml.safe_load(data)

# Avoid eval entirely; use ast.literal_eval for data only
import ast
ast.literal_eval(user_input)  # only parses literals
```

### Grep Detection Patterns

```bash
# SQL injection
grep -rn "execute(f\"" --include="*.py"
grep -rn "execute(\".*%s" --include="*.py" | grep -v "(.*,.*)"
grep -rn "\.format()" --include="*.py" | grep -i "select\|insert\|update\|delete"
grep -rn "\.raw(" --include="*.py"
grep -rn "\.extra(" --include="*.py"
grep -rn "RawSQL(" --include="*.py"
grep -rn 'text(f"' --include="*.py"

# Command injection
grep -rn "os\.system(" --include="*.py"
grep -rn "subprocess.*shell=True" --include="*.py"
grep -rn "os\.popen(" --include="*.py"

# Code execution
grep -rn "eval(" --include="*.py"
grep -rn "exec(" --include="*.py"
grep -rn "__import__(" --include="*.py"

# Deserialization
grep -rn "pickle\.loads\|pickle\.load(" --include="*.py"
grep -rn "yaml\.load(" --include="*.py" | grep -v "SafeLoader\|safe_load"
grep -rn "marshal\.loads(" --include="*.py"
```

---

## C2: Authentication

### Key Questions
- Is JWT algorithm pinned to a specific value (not accepting `alg` from token)?
- Is `verify_signature` set to `True` (or not explicitly `False`)?
- Is the JWT secret strong (not a short/guessable string)?
- Is Flask's `SECRET_KEY` set to a strong random value?
- Is Django's `SECRET_KEY` kept out of source code?
- Are password reset tokens single-use and time-limited?

### Commonly Missed
- PyJWT accepting `alg: none` (pre-2.x default behavior)
- `jwt.decode(token, options={"verify_signature": False})` in production code
- Flask session cookie forgery when `SECRET_KEY` is weak or default
- Django `SessionAuthentication` without CSRF on API views
- Password reset tokens that never expire
- Rate limiting absent on login endpoints

### Dangerous Patterns

```python
# PyJWT: algorithm none attack
jwt.decode(token, algorithms=["none"])
jwt.decode(token, options={"verify_signature": False})

# PyJWT: not pinning algorithm
jwt.decode(token, secret, algorithms=jwt.get_unverified_header(token)["alg"])

# Weak Flask secret
app.secret_key = "secret"
app.config["SECRET_KEY"] = "changeme"

# Django weak secret in settings.py
SECRET_KEY = "django-insecure-abc123"

# No expiry check
payload = jwt.decode(token, secret, algorithms=["HS256"],
                     options={"verify_exp": False})

# Password stored as hash without salt
hashlib.sha256(password.encode()).hexdigest()
```

### Safe Alternatives

```python
# PyJWT: pin algorithm, verify everything
payload = jwt.decode(token, secret, algorithms=["HS256"])
# verify_signature, verify_exp default to True in PyJWT >= 2.x

# Strong Flask secret
import secrets
app.secret_key = secrets.token_hex(32)

# Django: secret from environment
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# Password hashing with bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Or Django's built-in
from django.contrib.auth.hashers import make_password
make_password(password)
```

### Grep Detection Patterns

```bash
# JWT issues
grep -rn "verify_signature.*False" --include="*.py"
grep -rn "verify_exp.*False" --include="*.py"
grep -rn 'algorithms=\["none"\]' --include="*.py"
grep -rn "get_unverified_header" --include="*.py"

# Weak secrets
grep -rn "SECRET_KEY\s*=" --include="*.py"
grep -rn "secret_key\s*=" --include="*.py"
grep -rn 'app\.secret_key' --include="*.py"

# Weak password hashing
grep -rn "hashlib\.\(md5\|sha1\|sha256\)" --include="*.py" | grep -i "password\|passwd"
```

---

## C3: Authorization

### Key Questions
- Does every view/endpoint have an authentication check?
- Are resource lookups filtered by the authenticated user's ownership?
- Is role-based access control consistently applied?
- Can a regular user access admin endpoints?
- Are IDOR vulnerabilities prevented by scoping queries to the current user?

### Commonly Missed
- Django views missing `@login_required` or `LoginRequiredMixin`
- Flask views missing `@token_required` or equivalent decorator
- IDOR: `Object.objects.get(id=request.data["id"])` without owner check
- Django REST `ViewSet` allowing `destroy` or `update` without permission class
- FastAPI endpoints missing `Depends(get_current_user)`
- Admin routes relying only on URL obscurity

### Dangerous Patterns

```python
# Missing authentication - Django
def user_profile(request, user_id):
    user = User.objects.get(id=user_id)  # any visitor can view any profile
    return render(request, "profile.html", {"user": user})

# IDOR - no ownership check
@login_required
def edit_document(request, doc_id):
    doc = Document.objects.get(id=doc_id)  # should filter by request.user
    doc.content = request.POST["content"]
    doc.save()

# Flask: missing auth decorator
@app.route("/admin/users")
def admin_list_users():
    return jsonify(User.query.all())

# DRF: overly permissive ViewSet
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()  # no filtering by user
    serializer_class = OrderSerializer
    # missing permission_classes
```

### Safe Alternatives

```python
# Django: require login and check ownership
@login_required
def edit_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, owner=request.user)
    doc.content = request.POST["content"]
    doc.save()

# DRF: restrict queryset and add permissions
class OrderViewSet(viewsets.ModelViewSet):
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)

# Flask: auth decorator on all protected routes
@app.route("/admin/users")
@admin_required
def admin_list_users():
    return jsonify(User.query.all())
```

### Grep Detection Patterns

```bash
# Missing auth decorators - Django
grep -rn "^def " --include="views.py" | grep -v "login_required\|permission_required"

# IDOR - get without owner filter
grep -rn "\.objects\.get(id=" --include="*.py"
grep -rn "\.objects\.get(pk=" --include="*.py"

# DRF without permissions
grep -rn "class.*ViewSet" --include="*.py" -A 5 | grep -v "permission_classes"

# FastAPI missing auth
grep -rn "@app\.\(get\|post\|put\|delete\)" --include="*.py" -A 3 | grep -v "Depends\|current_user"
```

---

## C4: Mass Assignment

### Key Questions
- Are create/update operations accepting arbitrary user-supplied fields?
- Do Django ModelForms or DRF serializers explicitly declare allowed `fields`?
- Can a user set `is_admin`, `is_staff`, `role`, or `price` by adding extra fields to a request?
- Are SQLAlchemy models updated with unfiltered request data?
- Are Flask/FastAPI endpoints unpacking request JSON directly into ORM operations?

### Commonly Missed
- Django `Model.objects.create(**request.data)` allowing any field to be set
- DRF `ModelSerializer` with `fields = "__all__"` exposing writable sensitive fields
- DRF serializer missing `read_only_fields` for `is_staff`, `is_superuser`, `role`
- Django `ModelForm` without explicit `fields` or `exclude` (deprecated but still seen)
- Flask/SQLAlchemy `Model(**request.json)` passing unfiltered input to constructor
- SQLAlchemy `update().values(**request.json)` allowing arbitrary column updates
- FastAPI Pydantic models including fields that should not be user-settable

### Dangerous Patterns

```python
# Django: creating objects with unfiltered request data
user = User.objects.create(**request.data)  # attacker can set is_staff=True

# Django: updating with unfiltered data
User.objects.filter(id=uid).update(**request.data)  # can set is_admin=True

# DRF: serializer exposing all fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"  # includes is_staff, is_superuser

# DRF: missing read_only_fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["username", "email", "is_staff"]  # is_staff is writable

# Django ModelForm without explicit fields
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        # missing fields = [...] allows all model fields

# Flask/SQLAlchemy: unfiltered create
user = User(**request.json)  # attacker controls all columns
db.session.add(user)

# SQLAlchemy: unfiltered update
db.session.execute(
    update(User).where(User.id == uid).values(**request.json)
)

# FastAPI: Pydantic model with sensitive fields
class UserUpdate(BaseModel):
    username: str
    email: str
    role: str  # should not be user-settable
    is_admin: bool  # should not be user-settable
```

### Safe Alternatives

```python
# Django: whitelist fields explicitly
allowed = {"username", "email", "bio"}
filtered_data = {k: v for k, v in request.data.items() if k in allowed}
User.objects.filter(id=uid).update(**filtered_data)

# DRF: explicit fields with read_only_fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "is_staff"]
        read_only_fields = ["id", "is_staff"]

# Django ModelForm: explicit field list
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["username", "email", "bio"]

# Flask/SQLAlchemy: whitelist approach
allowed = {"username", "email", "bio"}
filtered = {k: v for k, v in request.json.items() if k in allowed}
user = User(**filtered)
db.session.add(user)

# FastAPI: separate models for create vs internal
class UserCreate(BaseModel):
    username: str
    email: str
    # role and is_admin intentionally excluded

class UserInternal(UserCreate):
    role: str = "user"
    is_admin: bool = False
```

### Grep Detection Patterns

```bash
# Django mass assignment
grep -rn "\.objects\.create(\*\*" --include="*.py"
grep -rn "\.objects\.filter.*\.update(\*\*" --include="*.py"
grep -rn "\.update(\*\*request\." --include="*.py"

# DRF overly broad serializers
grep -rn 'fields\s*=\s*"__all__"' --include="*.py"
grep -rn "class.*Serializer" --include="*.py" -A 10 | grep -v "read_only_fields"

# Django ModelForm without fields
grep -rn "class.*ModelForm" --include="*.py" -A 5 | grep -v "fields\s*="

# Flask/SQLAlchemy unfiltered
grep -rn "Model(\*\*request\." --include="*.py"
grep -rn "\.values(\*\*request\." --include="*.py"

# General unfiltered dict unpacking from request
grep -rn "\*\*request\.json\|\*\*request\.data\|\*\*request\.form" --include="*.py"
```

---

## C5: Data Exposure

### Key Questions
- Are passwords hashed with bcrypt/argon2/scrypt (not MD5/SHA)?
- Are API keys, tokens, and credentials stored outside source code?
- Is PII encrypted at rest in the database?
- Is TLS enforced for all connections?
- Are sensitive fields excluded from serialization/API responses?

### Commonly Missed
- Secrets committed in `settings.py`, `.env` files tracked in git
- Django `ModelSerializer` exposing password hashes via `fields = "__all__"`
- Flask/Django error pages leaking stack traces with local variables
- Passwords or tokens in URL query parameters (logged by proxies/browsers)
- `.env` files served by static file handlers

### Dangerous Patterns

```python
# Hardcoded credentials
DB_PASSWORD = "super_secret_123"
API_KEY = "sk-live-abc123def456"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Plaintext password storage
user.password = request.form["password"]  # no hashing

# Exposing all fields in API
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"  # includes password hash, tokens

# Sensitive data in URL
redirect(f"/callback?token={api_token}")

# PII in plain text files
with open("users_export.csv", "w") as f:
    f.write(f"{user.ssn},{user.name},{user.email}\n")
```

### Safe Alternatives

```python
# Credentials from environment
DB_PASSWORD = os.environ["DB_PASSWORD"]

# Explicit field listing excluding sensitive data
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email"]
        # Explicitly exclude password, tokens

# Encrypt PII at rest
from cryptography.fernet import Fernet
cipher = Fernet(os.environ["ENCRYPTION_KEY"])
encrypted_ssn = cipher.encrypt(ssn.encode())
```

### Grep Detection Patterns

```bash
# Hardcoded secrets
grep -rn "PASSWORD\s*=\s*[\"']" --include="*.py"
grep -rn "API_KEY\s*=\s*[\"']" --include="*.py"
grep -rn "SECRET\s*=\s*[\"']" --include="*.py"
grep -rn "TOKEN\s*=\s*[\"']" --include="*.py"
grep -rn "AWS_SECRET" --include="*.py"

# Overly broad serializers
grep -rn 'fields\s*=\s*"__all__"' --include="*.py"

# Sensitive data in URLs
grep -rn "redirect(.*token\|redirect(.*password\|redirect(.*secret" --include="*.py"
```

---

## C6: Misconfiguration

### Key Questions
- Is `DEBUG` set to `False` in production?
- Is `ALLOWED_HOSTS` configured restrictively?
- Are default credentials changed?
- Are CORS settings restrictive?
- Are security headers configured?
- Are verbose error messages disabled in production?

### Commonly Missed
- Flask `app.run(debug=True)` left in production code
- Django `ALLOWED_HOSTS = ["*"]`
- CORS allowing all origins: `CORS_ALLOW_ALL_ORIGINS = True`
- Django `SECURE_SSL_REDIRECT = False`
- Missing `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_SECURE`
- Exposed admin panels at default URLs (`/admin/`)

### Dangerous Patterns

```python
# Flask debug mode
app.run(debug=True)
app.config["DEBUG"] = True

# Django debug mode
DEBUG = True

# Overly permissive hosts
ALLOWED_HOSTS = ["*"]

# CORS wide open
CORS_ALLOW_ALL_ORIGINS = True
CORS_ORIGIN_ALLOW_ALL = True

# Missing security settings in Django
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0
X_FRAME_OPTIONS = "ALLOW"

# Default admin URL
urlpatterns = [
    path("admin/", admin.site.urls),  # predictable URL
]

# Verbose errors
app.config["PROPAGATE_EXCEPTIONS"] = True
# Flask returning full tracebacks to clients
```

### Safe Alternatives

```python
# Django production settings
DEBUG = False
ALLOWED_HOSTS = ["myapp.example.com"]
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# CORS: explicit origins
CORS_ALLOWED_ORIGINS = [
    "https://myapp.example.com",
]

# Flask production
app.run(debug=False)
```

### Grep Detection Patterns

```bash
# Debug mode
grep -rn "DEBUG\s*=\s*True" --include="*.py"
grep -rn "debug=True" --include="*.py"

# Permissive hosts
grep -rn 'ALLOWED_HOSTS.*\*' --include="*.py"

# CORS
grep -rn "CORS_ALLOW_ALL_ORIGINS\s*=\s*True" --include="*.py"
grep -rn "CORS_ORIGIN_ALLOW_ALL\s*=\s*True" --include="*.py"

# Missing security headers
grep -rn "SECURE_SSL_REDIRECT\s*=\s*False" --include="*.py"
grep -rn "SESSION_COOKIE_SECURE\s*=\s*False" --include="*.py"
grep -rn "X_FRAME_OPTIONS.*ALLOW" --include="*.py"

# Default admin path
grep -rn 'path("admin/"' --include="*.py"
grep -rn "url.*admin/" --include="*.py"
```

---

## C7: XSS

### Key Questions
- Are all template outputs auto-escaped?
- Is `|safe`, `mark_safe`, or `{% autoescape off %}` used with user data?
- Are CSP headers configured?
- Is user input reflected in HTML attributes or JavaScript blocks?

### Commonly Missed
- Jinja2 `|safe` filter applied to user-controlled data
- Django `mark_safe()` wrapping user input
- `{% autoescape off %}` blocks containing user data
- User input placed inside `<script>` tags in templates
- JSON data rendered into templates without escaping for HTML context
- SVG uploads containing JavaScript

### Dangerous Patterns

```python
# Jinja2: marking user data as safe
return render_template("page.html", content=user_input)
# In template: {{ content|safe }}

# Django: mark_safe with user data
from django.utils.safestring import mark_safe
def render_comment(comment):
    return mark_safe(f"<div>{comment.text}</div>")

# Autoescape disabled
# {% autoescape off %}
#   {{ user_comment }}
# {% endautoescape %}

# JSON in template without escaping
return render_template("page.html", data=json.dumps(user_data))
# In template: <script>var data = {{ data|safe }};</script>

# Jinja2 environment with autoescape off
env = Environment(loader=FileSystemLoader("templates"), autoescape=False)
```

### Safe Alternatives

```python
# Jinja2: autoescape enabled (default in Flask)
env = Environment(loader=FileSystemLoader("templates"), autoescape=True)

# Django: use |escape or rely on default auto-escaping
# {{ user_comment }}  -- auto-escaped by default

# JSON in templates: use tojson filter
# <script>var data = {{ data|tojson }};</script>

# CSP header
@app.after_request
def add_csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# Django CSP with django-csp
CSP_DEFAULT_SRC = ("'self'",)
```

### Grep Detection Patterns

```bash
# Jinja2/Flask unsafe output
grep -rn "|safe" --include="*.html" --include="*.jinja2"
grep -rn "mark_safe(" --include="*.py"
grep -rn "autoescape off" --include="*.html" --include="*.jinja2"
grep -rn "autoescape=False" --include="*.py"
grep -rn "Markup(" --include="*.py"

# User data in script blocks (check templates)
grep -rn "<script>" --include="*.html" -A 5 | grep "{{"

# Missing CSP
grep -rn "Content-Security-Policy" --include="*.py"
```

---

## C8: Dependencies

### Key Questions
- Has `pip audit` or `safety check` been run?
- Are there pinned versions with known CVEs?
- Are any dependencies end-of-life?
- Is `requirements.txt` or `Pipfile.lock` up to date?

### Commonly Missed
- Transitive dependencies with vulnerabilities
- Unpinned versions (`requests>=2.0`) pulling vulnerable releases
- `setup.py` dependencies not checked by audit tools
- Private packages shadowing public ones (dependency confusion)
- `pip install --extra-index-url` allowing package substitution

### High-Risk Packages to Check

| Package | Risk | Check for |
|---------|------|-----------|
| Django | Multiple CVEs per year | Version against known CVEs |
| Flask | Debug mode, older versions | Session cookie vulnerabilities |
| PyYAML | < 5.1 arbitrary code exec | `yaml.load` without SafeLoader |
| Pillow | Image processing CVEs | Buffer overflows in image parsing |
| cryptography | Periodic CVEs | Version currency |
| requests | < 2.20.0 CVE-2018-18074 | Credential leak on redirect |
| urllib3 | CRLF injection in older versions | Version check |
| Jinja2 | < 2.11.3 sandbox escape | Template injection |
| paramiko | < 2.10.1 auth bypass | Version check |

### Grep Detection Patterns

```bash
# Check for unpinned or loosely pinned deps
grep -rn ">=" requirements*.txt
grep -rn "==" requirements*.txt | grep -v "#"

# Check setup.py/pyproject.toml for deps
grep -rn "install_requires" setup.py
grep -rn "dependencies" pyproject.toml

# Extra index URLs (dependency confusion risk)
grep -rn "extra-index-url" pip.conf requirements*.txt
grep -rn "index-url" pip.conf requirements*.txt

# Run audit
# pip audit
# safety check -r requirements.txt
```

---

## C9: Cryptography

### Key Questions
- Is `secrets` module used for token generation (not `random`)?
- Are passwords hashed with bcrypt/argon2 (not MD5/SHA)?
- Is TLS 1.2+ enforced for outbound connections?
- Are encryption keys stored securely (not hardcoded)?
- Are IVs/nonces unique and randomly generated?

### Commonly Missed
- `random.randint()` for OTP codes or tokens
- `hashlib.md5(password)` or `hashlib.sha1(password)` for password storage
- Hardcoded encryption keys or IVs
- ECB mode encryption
- `verify=False` on HTTPS requests
- Weak RSA key sizes (< 2048 bits)

### Dangerous Patterns

```python
# Weak random for security tokens
import random
token = random.randint(100000, 999999)  # predictable OTP
reset_token = ''.join(random.choices(string.ascii_letters, k=32))

# Weak password hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha256(password.encode()).hexdigest()  # no salt

# Hardcoded encryption key
key = b"my-secret-key-16"
cipher = AES.new(key, AES.MODE_ECB)  # ECB mode is insecure

# Disabled TLS verification
requests.get(url, verify=False)
urllib3.disable_warnings(InsecureRequestWarning)

# Weak RSA key
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
```

### Safe Alternatives

```python
# Cryptographically secure random
import secrets
token = secrets.token_urlsafe(32)
otp = secrets.randbelow(900000) + 100000

# Strong password hashing
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Or argon2
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)

# AES-GCM with random IV
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

# TLS verification enabled (default)
requests.get(url)  # verify=True is default
```

### Grep Detection Patterns

```bash
# Weak random
grep -rn "random\.randint\|random\.choice\|random\.random" --include="*.py" | grep -i "token\|secret\|key\|otp\|code\|password\|session"

# Weak hashing
grep -rn "hashlib\.md5\|hashlib\.sha1" --include="*.py"
grep -rn "hashlib\.sha256" --include="*.py" | grep -i "password\|passwd"

# Hardcoded keys
grep -rn 'key\s*=\s*b"' --include="*.py"
grep -rn 'key\s*=\s*"' --include="*.py"

# ECB mode
grep -rn "MODE_ECB" --include="*.py"

# Disabled TLS
grep -rn "verify=False" --include="*.py"
grep -rn "disable_warnings" --include="*.py"

# Weak key size
grep -rn "key_size=1024\|key_size=512" --include="*.py"
```

---

## C10: SSRF

### Key Questions
- Does any code make HTTP requests to URLs derived from user input?
- Are webhook or callback URLs validated before use?
- Can users trigger requests to internal network addresses or cloud metadata endpoints?
- Do PDF generators, image processors, or link previewers fetch user-supplied URLs?
- Are URL scheme, host, and port validated and restricted to an allowlist?

### Commonly Missed
- `requests.get(user_url)` without any URL validation
- Cloud metadata endpoint access via `http://169.254.169.254/latest/meta-data/`
- DNS rebinding bypassing IP-based allowlists (domain resolves to internal IP after validation)
- Redirect-based bypasses: validated URL redirects to internal target
- PDF generators (WeasyPrint, pdfkit, xhtml2pdf) fetching user-controlled URLs including CSS/images
- URL shorteners or preview generators following user-supplied links
- Webhook registration endpoints accepting arbitrary callback URLs
- `file://`, `gopher://`, `dict://` scheme abuse when URL scheme is not restricted
- SSRF via XML external entities (XXE) in uploaded XML/SVG files
- Internal service scanning by iterating ports via URL parameter

### Dangerous Patterns

```python
# Direct request to user-controlled URL
import requests
response = requests.get(request.args["url"])  # SSRF

# urllib with user input
import urllib.request
data = urllib.request.urlopen(request.args["url"]).read()  # SSRF

# httpx with user input
import httpx
response = httpx.get(request.json["callback_url"])  # SSRF

# Webhook/callback URL without validation
def register_webhook(request):
    url = request.data["callback_url"]
    requests.post(url, json=event_data)  # attacker targets internal services

# PDF generation fetching user-controlled URLs
import pdfkit
pdfkit.from_url(request.args["url"], "output.pdf")  # SSRF

from weasyprint import HTML
HTML(url=request.args["url"]).write_pdf("output.pdf")  # SSRF

# Image/file fetching
def fetch_avatar(request):
    url = request.json["avatar_url"]
    img = requests.get(url).content  # can hit internal services

# Cloud metadata access (attacker supplies this URL)
# url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
requests.get(url)  # leaks cloud credentials

# Redirect-based bypass
# Attacker hosts redirect: https://evil.com -> http://169.254.169.254/...
requests.get(attacker_url, allow_redirects=True)  # follows to internal target
```

### Safe Alternatives

```python
# Validate URL against allowlist of domains/hosts
from urllib.parse import urlparse
import ipaddress

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
BLOCKED_SCHEMES = {"file", "gopher", "dict", "ftp"}

def validate_url(url):
    parsed = urlparse(url)
    # Block dangerous schemes
    if parsed.scheme.lower() in BLOCKED_SCHEMES:
        raise ValueError(f"Blocked URL scheme: {parsed.scheme}")
    # Enforce HTTPS
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS URLs are allowed")
    # Check against allowlist
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host not allowed: {parsed.hostname}")
    return url

# Resolve DNS and validate IP before request
import socket

def is_internal_ip(hostname):
    """Check if hostname resolves to a private/reserved IP."""
    try:
        ip = socket.getaddrinfo(hostname, None)[0][4][0]
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except (socket.gaierror, ValueError):
        return True  # fail closed

def safe_request(url):
    parsed = urlparse(url)
    if is_internal_ip(parsed.hostname):
        raise ValueError("Requests to internal addresses are blocked")
    return requests.get(url, allow_redirects=False, timeout=5)

# Disable redirects to prevent redirect-based bypass
response = requests.get(validated_url, allow_redirects=False, timeout=5)

# For webhooks: validate and persist URL, use async worker with egress controls
WEBHOOK_ALLOWED_SCHEMES = {"https"}
WEBHOOK_BLOCKED_CIDRS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# For PDF generators: use pre-fetched/sanitized content, not raw URLs
html_content = sanitize_html(user_html)  # strip external references
HTML(string=html_content).write_pdf("output.pdf")
```

### Grep Detection Patterns

```bash
# Direct SSRF vectors
grep -rn "requests\.get(\|requests\.post(\|requests\.put(\|requests\.head(" --include="*.py" | grep -i "request\.\|user\|param\|args\|input\|url"
grep -rn "urllib\.request\.urlopen(" --include="*.py"
grep -rn "httpx\.get(\|httpx\.post(\|httpx\.AsyncClient" --include="*.py"
grep -rn "aiohttp\.ClientSession" --include="*.py"

# Webhook/callback patterns
grep -rn "callback_url\|webhook_url\|notify_url" --include="*.py"

# PDF generators with URL input
grep -rn "pdfkit\.from_url\|pdfkit\.from_string" --include="*.py"
grep -rn "HTML(url=" --include="*.py"
grep -rn "xhtml2pdf\|weasyprint" --include="*.py"

# Cloud metadata indicators
grep -rn "169\.254\.169\.254" --include="*.py"
grep -rn "metadata\.google\|metadata\.azure" --include="*.py"

# URL from user input
grep -rn "request\.args\[.*url\|request\.json\[.*url\|request\.data\[.*url" --include="*.py" -i
grep -rn "request\.GET\[.*url\|request\.POST\[.*url" --include="*.py" -i
```

---

## C11: Logging & Monitoring

### Key Questions
- Are passwords, tokens, or API keys logged anywhere?
- Is PII (email, SSN, phone) logged without masking?
- Are log files protected from unauthorized access?
- Is log injection possible via user-controlled input?
- Are authentication events (login, logout, failure) logged?

### Commonly Missed
- `print(request.data)` or `print(request.headers)` including auth tokens
- `logging.debug(f"User data: {user.__dict__}")` exposing password hashes
- Log injection via newline characters in user input
- Django/Flask default loggers including POST data with passwords
- Sentry or error tracking capturing sensitive form fields

### Dangerous Patterns

```python
# Logging passwords
logger.info(f"Login attempt: user={username}, password={password}")
print(f"Request body: {request.json}")  # may contain passwords

# Logging tokens
logger.debug(f"Auth header: {request.headers['Authorization']}")
logger.info(f"API call with key: {api_key}")

# PII in logs
logger.info(f"New user registered: {user.email}, SSN: {user.ssn}")

# Log injection
# If username contains \n, attacker can forge log entries
logger.info(f"Login failed for user: {username}")

# Logging full objects
logger.debug(f"User object: {user.__dict__}")  # includes password hash

# Sentry capturing sensitive data
sentry_sdk.init(send_default_pii=True)
```

### Safe Alternatives

```python
# Mask sensitive fields
logger.info(f"Login attempt: user={username}")  # no password

# Sanitize log input (prevent injection)
safe_username = username.replace("\n", "").replace("\r", "")
logger.info(f"Login failed for user: {safe_username}")

# Structured logging with field filtering
import structlog
logger = structlog.get_logger()
logger.info("user_login", user_id=user.id)  # only log ID, not PII

# Sentry: filter sensitive data
sentry_sdk.init(
    send_default_pii=False,
    before_send=filter_sensitive_data,
)

# Django: filter sensitive POST params
LOGGING = {
    "filters": {
        "sensitive": {
            "()": "django.utils.log.CallbackFilter",
            "callback": filter_sensitive_params,
        }
    }
}
```

### Grep Detection Patterns

```bash
# Logging sensitive data
grep -rn "log.*password\|log.*passwd\|log.*token\|log.*secret\|log.*api_key" --include="*.py" -i
grep -rn "print(.*password\|print(.*token\|print(.*secret" --include="*.py" -i
grep -rn "logger\..*request\.headers" --include="*.py"
grep -rn "logger\..*request\.json\|logger\..*request\.data\|logger\..*request\.form" --include="*.py"
grep -rn "__dict__" --include="*.py" | grep -i "log\|print"

# Sentry PII
grep -rn "send_default_pii=True" --include="*.py"

# Print statements (often left from debugging)
grep -rn "^[[:space:]]*print(" --include="*.py" | grep -v "test_\|_test\.py"
```

---

## C12: Infrastructure (IaC)

### Key Questions
- Does the container run as non-root?
- Are secrets passed via environment variables (not hardcoded in Dockerfiles)?
- Are images pinned to specific digests (not just `latest`)?
- Are resource limits set?
- Is multi-stage build used to minimize attack surface?

### Commonly Missed
- `docker-compose.yml` mounting host filesystem broadly
- Secrets in `docker-compose.yml` environment section (committed to git)
- `RUN pip install` without `--no-cache-dir`
- Base images with known vulnerabilities
- Missing health checks
- Running as root by default

### Dangerous Patterns

```dockerfile
# Running as root (default)
FROM python:3.11
COPY . /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
# No USER directive = runs as root

# Secrets in Dockerfile
ENV API_KEY=sk-live-abc123
ENV DB_PASSWORD=supersecret

# Unpinned base image
FROM python:latest

# Installing unnecessary tools
RUN apt-get install -y curl wget netcat vim
```

```yaml
# docker-compose.yml: secrets in plain text
services:
  app:
    environment:
      - DB_PASSWORD=mysecret
      - API_KEY=sk-live-abc123
    volumes:
      - /:/host  # mounting entire host filesystem
    privileged: true
```

### Safe Alternatives

```dockerfile
# Multi-stage build, non-root user, pinned image
FROM python:3.11.7-slim@sha256:abc123... AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11.7-slim@sha256:abc123...
RUN useradd --create-home appuser
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY . .
USER appuser
HEALTHCHECK CMD ["python", "-c", "import requests; requests.get('http://localhost:8000/health')"]
CMD ["python", "app.py"]
```

```yaml
# docker-compose.yml: secrets via docker secrets or env_file
services:
  app:
    env_file: .env  # .env in .gitignore
    read_only: true
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "0.5"
```

### Grep Detection Patterns

```bash
# Dockerfile issues
grep -rn "^FROM.*latest" Dockerfile*
grep -rn "^ENV.*PASSWORD\|^ENV.*SECRET\|^ENV.*KEY\|^ENV.*TOKEN" Dockerfile*
grep -n "USER" Dockerfile* | head -1  # check if USER directive exists
grep -rn "privileged" docker-compose*.yml

# Docker-compose secrets
grep -rn "PASSWORD\|SECRET\|KEY\|TOKEN" docker-compose*.yml | grep -v "#"

# Host mounts
grep -rn "volumes:" docker-compose*.yml -A 5 | grep "/:/\|/etc\|/var"

# Missing resource limits
grep -rn "resources:" docker-compose*.yml  # should exist

# Kubernetes manifests
grep -rn "privileged: true" --include="*.yaml" --include="*.yml"
grep -rn "runAsRoot\|runAsUser: 0" --include="*.yaml" --include="*.yml"
grep -rn "hostNetwork: true" --include="*.yaml" --include="*.yml"
```
