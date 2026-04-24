# Flask/Python Web Framework - Security Vulnerability Reference

## Identification Features

```bash
# Detect Flask usage
grep -r "from flask import\|import flask" --include="*.py"
grep -r "Flask(__name__)" --include="*.py"
grep -r "flask" requirements.txt setup.py pyproject.toml Pipfile
grep -r "FLASK_APP\|FLASK_ENV" .env .flaskenv
```

Common file patterns: `app.py`, `wsgi.py`, `__init__.py` with Flask factory pattern, `templates/` directory with Jinja2 files.

---

## Critical Vulnerabilities

### 1. Debug Mode Remote Code Execution

The Werkzeug interactive debugger allows arbitrary Python code execution when `debug=True`. If the debugger PIN is leaked or brute-forced, an attacker gains full RCE on the server.

**Dangerous:**
```python
# app.py - Debug mode enabled in production
app = Flask(__name__)
app.run(debug=True, host='0.0.0.0')

# Or via environment variable
# FLASK_DEBUG=1 flask run --host=0.0.0.0
```

**Safe:**
```python
# app.py - Debug mode disabled, use production WSGI server
app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=False)

# Production: use gunicorn
# gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

**Detection:**
```bash
grep -rn "debug=True\|debug = True" --include="*.py"
grep -rn "FLASK_DEBUG.*1\|FLASK_ENV.*development" .env .flaskenv
grep -rn "app\.run(" --include="*.py"
grep -rn "use_debugger\|use_reloader" --include="*.py"
```

### 2. SECRET_KEY Exposure

A weak or hardcoded SECRET_KEY allows session forgery, CSRF token prediction, and signature bypass.

**Dangerous:**
```python
app.secret_key = 'dev'
app.config['SECRET_KEY'] = 'mysecretkey123'
app.config['SECRET_KEY'] = 'change-me'
SECRET_KEY = 'super-secret'  # in config.py committed to git
```

**Safe:**
```python
import os
import secrets

# Generate a strong random key
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Or load from a file not in version control
with open('/etc/app/secret_key', 'r') as f:
    app.config['SECRET_KEY'] = f.read().strip()
```

**Detection:**
```bash
grep -rn "secret_key\|SECRET_KEY" --include="*.py" --include="*.cfg"
grep -rn "secret_key.*=.*['\"]" --include="*.py"
# Check for short/common keys
grep -rn "SECRET_KEY.*=.*['\"][a-zA-Z0-9]\{1,20\}['\"]" --include="*.py"
```

### 3. Server-Side Template Injection (SSTI)

Jinja2 SSTI allows RCE when user input is rendered as a template string rather than passed as a template variable.

**Dangerous:**
```python
from flask import render_template_string, request

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # User input directly in template string
    template = f"<h1>Hello {name}</h1>"
    return render_template_string(template)

# Also dangerous: constructing templates from user input
@app.route('/page')
def page():
    content = request.form.get('content')
    return render_template_string(content)  # Full SSTI
```

**Safe:**
```python
from flask import render_template_string, request

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # Pass user input as a variable, not in the template string
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)

# Better: use template files
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return render_template('greet.html', name=name)
```

**Detection:**
```bash
grep -rn "render_template_string" --include="*.py"
grep -rn "Template(.*request\|Template(.*input" --include="*.py"
grep -rn "\.format(\|f['\"].*{.*request" --include="*.py" | grep -i "template\|render\|jinja"
grep -rn "Environment(.*autoescape.*False" --include="*.py"
```

### 4. Jinja2 Autoescape Disabled / `|safe` Filter Abuse

Disabling autoescape or using `|safe` on user-controlled data enables XSS and can escalate to SSTI.

**Dangerous:**
```python
# In template: autoescape disabled
{% autoescape false %}
  {{ user_input }}
{% endautoescape %}

# In template: safe filter on user data
<div>{{ user_comment|safe }}</div>

# In Python: Markup wrapping user input
from markupsafe import Markup
return Markup(user_input)
```

**Safe:**
```python
# Let Jinja2 autoescape handle it (default in Flask)
<div>{{ user_comment }}</div>

# If HTML is needed, sanitize first
import bleach
clean_html = bleach.clean(user_input, tags=['b', 'i', 'em', 'strong'], strip=True)
return render_template('page.html', content=Markup(clean_html))
```

**Detection:**
```bash
grep -rn "|safe" --include="*.html" --include="*.jinja2"
grep -rn "autoescape false\|autoescape off" --include="*.html" --include="*.jinja2"
grep -rn "Markup(" --include="*.py"
grep -rn "autoescape=False\|autoescape=None" --include="*.py"
```

### 5. Pickle Session Deserialization RCE

Using pickle-based session backends allows attackers with the SECRET_KEY (or a weak one) to craft malicious session cookies that execute arbitrary code on deserialization.

**Dangerous:**
```python
# Using pickle-based server-side sessions
from flask_session import Session

app.config['SESSION_TYPE'] = 'filesystem'  # Uses pickle by default
app.config['SESSION_TYPE'] = 'redis'       # Uses pickle by default
Session(app)

# Custom cookie with pickle
import pickle
data = pickle.loads(request.cookies.get('data'))
```

**Safe:**
```python
# Use signed JSON sessions (Flask default) - no pickle
# Or configure session serializer to JSON
from flask_session import Session

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_SERIALIZER'] = 'json'  # Avoid pickle
Session(app)

# Never unpickle user-controlled data
import json
data = json.loads(request.cookies.get('data'))
```

**Detection:**
```bash
grep -rn "pickle\.\|cPickle\.\|shelve\." --include="*.py"
grep -rn "SESSION_TYPE" --include="*.py" --include="*.cfg"
grep -rn "loads\(.*request\|loads\(.*cookie" --include="*.py"
grep -rn "SESSION_SERIALIZER" --include="*.py"
```

---

## High Vulnerabilities

### 6. SQL Injection via Raw Queries

Using string formatting or concatenation in SQL queries allows injection.

**Dangerous:**
```python
from flask import request
import sqlite3

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    db = sqlite3.connect('app.db')
    # String formatting in SQL
    cursor = db.execute(f"SELECT * FROM users WHERE id = {user_id}")
    cursor = db.execute("SELECT * FROM users WHERE id = " + user_id)
    cursor = db.execute("SELECT * FROM users WHERE id = %s" % user_id)
    return str(cursor.fetchall())
```

**Safe:**
```python
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    db = sqlite3.connect('app.db')
    # Parameterized query
    cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchall())

# With SQLAlchemy ORM (preferred)
user = User.query.filter_by(id=user_id).first()
```

**Detection:**
```bash
grep -rn "execute(.*f['\"].*SELECT\|execute(.*f['\"].*INSERT\|execute(.*f['\"].*UPDATE\|execute(.*f['\"].*DELETE" --include="*.py"
grep -rn "execute(.*%.*request\|execute(.*+.*request\|execute(.*\.format(" --include="*.py"
grep -rn "text(.*f['\"].*SELECT" --include="*.py"  # SQLAlchemy text()
```

### 7. Command Injection

Passing user input to OS commands without sanitization.

**Dangerous:**
```python
import os
import subprocess

@app.route('/ping')
def ping():
    host = request.args.get('host')
    output = os.popen(f"ping -c 1 {host}").read()
    output = subprocess.check_output(f"nslookup {host}", shell=True)
    os.system("convert " + request.form['filename'])
    return output
```

**Safe:**
```python
import subprocess
import shlex
import re

@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Validate input
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        return "Invalid hostname", 400
    # Use list form (no shell=True)
    output = subprocess.check_output(['ping', '-c', '1', host])
    return output
```

**Detection:**
```bash
grep -rn "os\.popen\|os\.system\|subprocess\.call\|subprocess\.Popen\|subprocess\.check_output" --include="*.py"
grep -rn "shell=True" --include="*.py"
grep -rn "eval(\|exec(" --include="*.py"
```

### 8. File Upload Without Validation

Accepting file uploads without type/size validation can lead to RCE, path traversal, or denial of service.

**Dangerous:**
```python
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    # No validation of file type, name, or size
    f.save(os.path.join('/uploads', f.filename))  # Path traversal via filename
    return 'Uploaded'
```

**Safe:**
```python
from werkzeug.utils import secure_filename
import os

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    if f and allowed_file(f.filename):
        filename = secure_filename(f.filename)
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return 'Uploaded'
    return 'Invalid file type', 400
```

**Detection:**
```bash
grep -rn "request\.files" --include="*.py"
grep -rn "\.save(" --include="*.py" | grep -v "secure_filename"
grep -rn "MAX_CONTENT_LENGTH" --include="*.py"
grep -rn "secure_filename" --include="*.py"
```

### 9. Server-Side Request Forgery (SSRF)

Fetching URLs supplied by users without validation can allow access to internal services.

**Dangerous:**
```python
import requests

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # No URL validation, no allow-list
    resp = requests.get(url)
    return resp.text

@app.route('/webhook')
def webhook():
    callback = request.json.get('callback_url')
    # Disabling SSL verification compounds the risk
    requests.post(callback, data=payload, verify=False)
```

**Safe:**
```python
import requests
from urllib.parse import urlparse
import ipaddress

ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    if parsed.hostname in ALLOWED_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False
    except ValueError:
        pass
    return False

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    if not is_safe_url(url):
        return 'URL not allowed', 403
    resp = requests.get(url, timeout=5, verify=True)
    return resp.text
```

**Detection:**
```bash
grep -rn "requests\.get\|requests\.post\|requests\.put\|urllib\.request\|urlopen\|httpx" --include="*.py"
grep -rn "verify=False\|verify\s*=\s*False" --include="*.py"
grep -rn "request\.args.*url\|request\.form.*url\|request\.json.*url" --include="*.py"
```

### 10. JWT Vulnerabilities

Algorithm confusion, missing expiry, and weak secrets in JWT implementations.

**Dangerous:**
```python
import jwt

# Weak secret
token = jwt.encode(payload, 'secret123', algorithm='HS256')

# No algorithm restriction on decode (alg:none attack)
data = jwt.decode(token, 'secret', options={"verify_signature": False})

# No expiry set
payload = {'user_id': user.id}  # Missing 'exp' claim
token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Accepting alg from token header without restriction
header = jwt.get_unverified_header(token)
data = jwt.decode(token, SECRET_KEY, algorithms=[header['alg']])
```

**Safe:**
```python
import jwt
from datetime import datetime, timedelta, timezone

# Strong secret (or use RSA keys)
SECRET_KEY = os.environ['JWT_SECRET']  # 256-bit minimum

# Set expiry and required claims
payload = {
    'user_id': user.id,
    'exp': datetime.now(timezone.utc) + timedelta(hours=1),
    'iat': datetime.now(timezone.utc),
    'iss': 'myapp'
}
token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Strict decode with fixed algorithm list
data = jwt.decode(
    token, SECRET_KEY,
    algorithms=['HS256'],  # Fixed list, never from token header
    options={"require": ["exp", "iat", "iss"]}
)
```

**Detection:**
```bash
grep -rn "jwt\.encode\|jwt\.decode\|PyJWT\|python-jose" --include="*.py"
grep -rn "verify_signature.*False\|verify.*False" --include="*.py" | grep -i jwt
grep -rn "algorithms=\[.*header\|algorithms=\[.*alg" --include="*.py"
grep -rn "\"exp\"\|'exp'" --include="*.py" | grep -i "jwt\|token\|payload"
```

---

## Medium Vulnerabilities

### 11. CSRF Protection Missing

Flask does not include CSRF protection by default.

**Dangerous:**
```python
# No CSRF protection at all
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    to_account = request.form['to']
    do_transfer(amount, to_account)
    return 'Done'
```

**Safe:**
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# All POST forms now require CSRF token
# In templates:
# <form method="post">
#   <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
#   ...
# </form>

# For AJAX requests, set the X-CSRFToken header
```

**Detection:**
```bash
grep -rn "CSRFProtect\|csrf_token\|WTF_CSRF" --include="*.py" --include="*.html"
grep -rn "methods=.*POST\|methods=.*PUT\|methods=.*DELETE" --include="*.py"
grep -rn "csrf\.exempt\|@csrf\.exempt" --include="*.py"
```

### 12. Open Redirect

Redirecting to user-supplied URLs without validation.

**Dangerous:**
```python
from flask import redirect, request

@app.route('/login')
def login():
    next_url = request.args.get('next')
    if authenticate(request):
        return redirect(next_url)  # Attacker: /login?next=https://evil.com
```

**Safe:**
```python
from flask import redirect, request, url_for
from urllib.parse import urlparse

def is_safe_redirect(target):
    host = urlparse(target).netloc
    return host == '' or host == urlparse(request.host_url).netloc

@app.route('/login')
def login():
    next_url = request.args.get('next', url_for('index'))
    if authenticate(request):
        if is_safe_redirect(next_url):
            return redirect(next_url)
        return redirect(url_for('index'))
```

**Detection:**
```bash
grep -rn "redirect(.*request\.\|redirect(.*args\|redirect(.*form" --include="*.py"
grep -rn "next.*=.*request\|return_to.*=.*request\|redirect_uri.*=.*request" --include="*.py"
```

### 13. Session Cookie Security Flags

Missing Secure, HttpOnly, or SameSite flags on session cookies.

**Dangerous:**
```python
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = None
# Or simply not setting these at all
```

**Safe:**
```python
app.config['SESSION_COOKIE_SECURE'] = True      # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True      # No JS access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'    # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
```

**Detection:**
```bash
grep -rn "SESSION_COOKIE_SECURE\|SESSION_COOKIE_HTTPONLY\|SESSION_COOKIE_SAMESITE" --include="*.py"
grep -rn "PERMANENT_SESSION_LIFETIME" --include="*.py"
```

### 14. CORS Misconfiguration

Overly permissive CORS settings.

**Dangerous:**
```python
from flask_cors import CORS

CORS(app)  # Allow all origins by default
CORS(app, origins='*', supports_credentials=True)

# Or manual headers
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

**Safe:**
```python
from flask_cors import CORS

CORS(app, origins=['https://myapp.com', 'https://admin.myapp.com'],
     supports_credentials=True,
     methods=['GET', 'POST'],
     allow_headers=['Content-Type', 'Authorization'])
```

**Detection:**
```bash
grep -rn "CORS(\|flask.cors\|flask_cors" --include="*.py"
grep -rn "Access-Control-Allow-Origin.*\*" --include="*.py"
grep -rn "supports_credentials.*True" --include="*.py"
```

---

## Framework Extension Security

### 15. Flask-Login Bypass

**Dangerous:**
```python
from flask_login import login_required

# Missing @login_required on sensitive route
@app.route('/admin/users')
def admin_users():
    return get_all_users()

# Trusting user_loader without validation
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)  # No active/banned check
```

**Safe:**
```python
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    return get_all_users()

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user and user.is_active and not user.is_banned:
        return user
    return None
```

**Detection:**
```bash
grep -rn "@app\.route\|@blueprint\.route" --include="*.py" | grep -v "login_required"
grep -rn "user_loader" --include="*.py"
grep -rn "login_required" --include="*.py"
```

### 16. Flask-JWT-Extended Misconfiguration

**Dangerous:**
```python
app.config['JWT_SECRET_KEY'] = 'changeme'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False  # Tokens never expire
app.config['JWT_ALGORITHM'] = 'none'
```

**Safe:**
```python
app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_BLACKLIST_ENABLED'] = True
```

**Detection:**
```bash
grep -rn "JWT_SECRET_KEY\|JWT_ACCESS_TOKEN_EXPIRES\|JWT_ALGORITHM" --include="*.py"
grep -rn "JWT_BLACKLIST_ENABLED\|JWT_BLOCKLIST_ENABLED" --include="*.py"
```

### 17. Flask-CORS Wildcard with Credentials

**Dangerous:**
```python
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
```

**Safe:**
```python
CORS(app, resources={r"/api/*": {
    "origins": ["https://myapp.com"],
    "methods": ["GET", "POST"],
    "allow_headers": ["Authorization", "Content-Type"]
}}, supports_credentials=True)
```

**Detection:**
```bash
grep -rn "origins.*\*.*credentials\|credentials.*origins.*\*" --include="*.py"
grep -rn "CORS(" --include="*.py"
```

---

## Detection Commands

```bash
# Full Flask security scan
echo "=== Debug Mode ==="
grep -rn "debug=True\|FLASK_DEBUG=1" --include="*.py" --include=".env" --include=".flaskenv"

echo "=== Secret Key ==="
grep -rn "SECRET_KEY\|secret_key" --include="*.py" --include="*.cfg" --include="*.env"

echo "=== Template Injection ==="
grep -rn "render_template_string" --include="*.py"
grep -rn "|safe" --include="*.html" --include="*.jinja2"
grep -rn "autoescape false" --include="*.html" --include="*.jinja2"

echo "=== SQL Injection ==="
grep -rn "execute(.*f['\"].*SELECT\|\.execute(.*%.*\|\.execute(.*+.*\|text(.*f['\"]" --include="*.py"

echo "=== Command Injection ==="
grep -rn "os\.system\|os\.popen\|subprocess.*shell=True\|eval(\|exec(" --include="*.py"

echo "=== Deserialization ==="
grep -rn "pickle\.\|yaml\.load\|yaml\.unsafe_load\|marshal\.loads" --include="*.py"

echo "=== SSRF ==="
grep -rn "requests\.get\|requests\.post\|urlopen\|httpx\.get" --include="*.py" | grep -i "request\.\|args\.\|form\.\|json\."

echo "=== File Upload ==="
grep -rn "request\.files" --include="*.py"
grep -rn "secure_filename" --include="*.py"

echo "=== Missing Security Headers ==="
grep -rn "SESSION_COOKIE_SECURE\|SESSION_COOKIE_HTTPONLY" --include="*.py"
grep -rn "CSRFProtect\|WTF_CSRF" --include="*.py"
```

---

## Audit Checklist

- [ ] `debug=True` is NOT used in production
- [ ] `SECRET_KEY` is strong (32+ bytes), loaded from environment, not in source control
- [ ] No `render_template_string()` with user input
- [ ] `|safe` filter only used on sanitized content
- [ ] `{% autoescape false %}` not used with user data
- [ ] No pickle deserialization of user-controlled data
- [ ] All SQL queries use parameterized statements
- [ ] No `os.system()` / `subprocess(shell=True)` with user input
- [ ] File uploads validate type, size, and use `secure_filename()`
- [ ] SSRF: outbound requests validate URLs against allow-list
- [ ] JWT tokens have expiry, use fixed algorithm list, strong secret
- [ ] CSRF protection enabled (Flask-WTF CSRFProtect)
- [ ] Session cookies have Secure, HttpOnly, SameSite flags
- [ ] CORS origins are explicitly listed (no wildcard with credentials)
- [ ] `@login_required` on all authenticated routes
- [ ] Flask-Login `user_loader` checks active/banned status
- [ ] No `verify=False` in requests/HTTP calls
- [ ] Error handlers do not leak stack traces in production
