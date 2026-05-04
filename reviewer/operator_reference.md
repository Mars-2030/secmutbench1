# Operator Reference — SecMutBench v2.8.0

This document describes all 25 mutation operators used in SecMutBench.
Each operator models a specific class of security vulnerability introduction.

## Summary Table

| Operator | CWEs | Mutants | Description |
|----------|------|---------|-------------|
| CSRF_REMOVE | CWE-352 | 82 | Removes CSRF token validation, allowing cross-site request forgery attacks. |
| DESERIAL | CWE-502, CWE-94 | 106 | Replaces safe deserialization (json.loads) with unsafe methods (pickle.loads, ya |
| EVALINJECT | CWE-94, CWE-95 | 98 | Replaces safe code evaluation (AST parsing) with unsafe eval()/exec(), enabling  |
| FILEUPLOAD | CWE-434 | 35 | Removes file upload validation (extension, MIME type, size checks), allowing mal |
| HARDCODE | CWE-798 | 81 | Introduces hardcoded credentials, API keys, or secrets instead of secure retriev |
| IDOR | CWE-639 | 20 | Removes object-level authorization checks, allowing access to other users' resou |
| INFOEXPOSE | CWE-209 | 34 | Exposes detailed error messages, stack traces, or internal paths to users. |
| INPUTVAL | CWE-20, CWE-400 | 119 | Bypasses or weakens input validation logic (conditions, length checks, type chec |
| LDAPINJECT | CWE-643 | 56 | Removes LDAP query sanitization, allowing LDAP injection through user input. |
| LOGINJECT | CWE-117 | 62 | Removes log sanitization (newline stripping, encoding), enabling log injection/f |
| MISSINGAUTH | CWE-862, CWE-863 | 83 | Removes authorization checks (role verification, ownership validation), allowing |
| NOCERTVALID | CWE-295 | 60 | Disables SSL/TLS certificate validation (verify=False), enabling MITM attacks. |
| OPENREDIRECT | CWE-601 | 63 | Removes URL validation on redirects, allowing redirection to attacker-controlled |
| PATHCONCAT | CWE-22 | 87 | Replaces safe path resolution (os.path.join + realpath checks) with unsafe strin |
| PSQLI | CWE-89 | 80 | Converts parameterized SQL queries to string concatenation/interpolation, introd |
| REGEXDOS | CWE-400 | 24 | Introduces vulnerable regex patterns susceptible to catastrophic backtracking (R |
| RENCRYPT | CWE-319 | 90 | Removes or weakens encryption of sensitive data in transit or at rest. |
| RMAUTH | CWE-306, CWE-862 | 105 | Removes authentication checks (is_authenticated, verify_token), allowing unauthe |
| RVALID | CWE-20, CWE-74, CWE-79, CWE-915 | 151 | Removes input validation checks (sanitization, escaping, filtering), allowing un |
| SSRF | CWE-918 | 97 | Removes URL validation (hostname checks, scheme restrictions), allowing internal |
| WEAKCRYPTO | CWE-327, CWE-328 | 128 | Replaces strong cryptographic algorithms (SHA-256, bcrypt) with weak ones (MD5,  |
| WEAKKEY | CWE-326 | 47 | Reduces cryptographic key sizes below recommended minimums (e.g., RSA 512 instea |
| WEAKPERM | CWE-732 | 60 | Weakens file permissions (e.g., 0o600 to 0o777), making sensitive files world-re |
| WEAKRANDOM | CWE-338 | 45 | Replaces cryptographic random (secrets, os.urandom) with predictable random (ran |
| XXE | CWE-611 | 56 | Replaces safe XML parsing (defusedxml) with standard xml.etree that allows entit |

---

## CSRF_REMOVE

**Description**: Removes CSRF token validation, allowing cross-site request forgery attacks.
**Target CWEs**: CWE-352
**Total mutants**: 82 (38 CWE-specific, 44 generic)

**Mutation variants produced**:
- Removed CSRF validation block
- [CWE-352] Added @csrf_exempt
- [Generic] Removed security guard (simple_guard)
- [Generic] Dead security check (simple_guard, pass instead of raise)

**Example** (CWE-352, Removed CSRF validation block):

Secure code:
```python
def handle_form(request):
    """Handle form with CSRF validation."""
    if request.method == "POST":
        token = request.form.get("csrf_token")
        if not token or token != request.session.get("csrf_token"):
            raise ValueError("CSRF validation failed")
    return process_data(request.form)
```

Mutant code:
```python
def handle_form(request):
    """Handle form with CSRF validation."""
    if request.method == "POST":
        token = request.form.get("csrf_token")
        pass  # CSRF validation removed
    return process_data(request.form)
```

---

## DESERIAL

**Description**: Replaces safe deserialization (json.loads) with unsafe methods (pickle.loads, yaml.load).
**Target CWEs**: CWE-502, CWE-94
**Total mutants**: 106 (43 CWE-specific, 63 generic)

**Mutation variants produced**:
- json.loads → pickle.loads
- json.loads → yaml.unsafe_load
- json.loads → eval
- [CWE-502] Replaced json.loads with pickle.loads

**Example** (CWE-502, json.loads → pickle.loads):

Secure code:
```python
import json
def load_session(session_data):
    """Load session safely with JSON."""
    return json.loads(session_data)
```

Mutant code:
```python
import pickle
import json
def load_session(session_data):
    """Load session safely with JSON."""
    return pickle.loads(session_data)
```

---

## EVALINJECT

**Description**: Replaces safe code evaluation (AST parsing) with unsafe eval()/exec(), enabling code injection.
**Target CWEs**: CWE-94, CWE-95
**Total mutants**: 98 (50 CWE-specific, 48 generic)

**Mutation variants produced**:
- ast.parse → eval (code injection)
- ast.parse → eval (code injection)
- [CWE-94] Removed ast.ImportFrom from validation
- [CWE-94] Removed ast.Call from validation (allows function calls)

**Example** (CWE-94, ast.parse → eval (code injection)):

Secure code:
```python
import ast
def run_code_snippet(code):
    """Run code snippet with validation."""
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)):
            raise ValueError("Imports and function calls not allowed")
    # Only allow simple assignments
    compiled = compile(tree, '<string>', 'exec')
    safe_globals = {"__builtins__": {}}
    exec(compiled, safe_globals)
    return "executed"
```

Mutant code:
```python
import ast
def run_code_snippet(code):
    """Run code snippet with validation."""
    return eval(code)
```

---

## FILEUPLOAD

**Description**: Removes file upload validation (extension, MIME type, size checks), allowing malicious uploads.
**Target CWEs**: CWE-434
**Total mutants**: 35 (15 CWE-specific, 20 generic)

**Mutation variants produced**:
- Replaced 'not in ALLOWED_EXTENSIONS' with False (always allowed)
- Dead file extension check (pass instead of raise)
- [CWE-434] Added dangerous extensions to allowed list
- [Generic] Removed security guard (simple_guard)

---

## HARDCODE

**Description**: Introduces hardcoded credentials, API keys, or secrets instead of secure retrieval.
**Target CWEs**: CWE-798
**Total mutants**: 81 (67 CWE-specific, 14 generic)

**Mutation variants produced**:
- [Easy] Replaced os.environ['DB_HOST'] with hardcoded value
- [Easy] Replaced os.environ['DB_USER'] with hardcoded value
- [Easy-V1] Replaced os.environ['DB_PASSWORD'] with "password"
- [Easy-V2] Replaced os.environ['DB_PASSWORD'] with "123456"

**Example** (CWE-798, [Easy] Replaced os.environ['DB_HOST'] with hardcoded value):

Secure code:
```python
import os
def connect_to_db():
    """Connect to database with env vars."""
    return mysql.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"]
    )
```

Mutant code:
```python
import os
def connect_to_db():
    """Connect to database with env vars."""
    return mysql.connect(
        host="admin123",
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"]
    )
```

---

## IDOR

**Description**: Removes object-level authorization checks, allowing access to other users' resources.
**Target CWEs**: CWE-639
**Total mutants**: 20 (10 CWE-specific, 10 generic)

**Mutation variants produced**:
- Replaced user ID check with False
- Dead user authorization check (pass instead of raise)
- [Generic] Removed security guard (simple_guard)
- [Generic] Bypassed security condition (simple_guard)

**Example** (CWE-639, Replaced user ID check with False):

Secure code:
```python
def get_profile(user_id, current_user_id):
    """Get user profile with authorization check."""
    if user_id != current_user_id:
        raise PermissionError("Cannot access other user's profile")
    return db.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
```

Mutant code:
```python
def get_profile(user_id, current_user_id):
    """Get user profile with authorization check."""
    if False:
        raise PermissionError("Cannot access other user's profile")
    return db.execute("SELECT * FROM profiles WHERE user_id = ?", (user_id,))
```

---

## INFOEXPOSE

**Description**: Exposes detailed error messages, stack traces, or internal paths to users.
**Target CWEs**: CWE-209
**Total mutants**: 34 (34 CWE-specific, 0 generic)

**Mutation variants produced**:
- Exposed error details in response
- [CWE-209] Exposed raw error message
- [CWE-209] Added traceback to error response
- [CWE-209] Exposed error type information

**Example** (CWE-209, Exposed error details in response):

Secure code:
```python
import logging
logger = logging.getLogger(__name__)
def handle_db_error(error):
    """Handle database error without exposing details."""
    logger.error(f"Database error: {error}")
    return {"error": "A database error occurred", "code": "DB_ERROR"}
```

Mutant code:
```python
import logging
logger = logging.getLogger(__name__)
def handle_db_error(error):
    """Handle database error without exposing details."""
    logger.error(f"Database error: {error}")
    return {"error": str(error), "details": repr(error), "code": "DB_ERROR"}
```

---

## INPUTVAL

**Description**: Bypasses or weakens input validation logic (conditions, length checks, type checks).
**Target CWEs**: CWE-20, CWE-400
**Total mutants**: 119 (34 CWE-specific, 85 generic)

**Mutation variants produced**:
- [Medium] Removed regex pattern validation
- [Easy] Removed string contains check
- [Easy] Removed empty/null check
- [Easy] Dead empty/null check (pass instead of raise)

**Example** (CWE-20, [Medium] Removed regex pattern validation):

Secure code:
```python
import re
import os
def sanitize_filename(name):
    """Sanitize filename rejecting dangerous chars."""
    if not name:
        raise ValueError("Empty filename")
    # Remove path separators and dangerous chars
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError("Path traversal not allowed")
    # Only allow alphanumeric, underscore, hyphen, dot
    if not re.match(r'^[a-zA-Z0-9_.-]+$', name):
        raise ValueError("Invalid filename characters")
    return name
```

Mutant code:
```python
import re
import os
def sanitize_filename(name):
    """Sanitize filename rejecting dangerous chars."""
    if not name:
        raise ValueError("Empty filename")
    # Remove path separators and dangerous chars
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError("Path traversal not allowed")
    # Only allow alphanumeric, underscore, hyphen, dot
        return name
```

---

## LDAPINJECT

**Description**: Removes LDAP query sanitization, allowing LDAP injection through user input.
**Target CWEs**: CWE-643
**Total mutants**: 56 (24 CWE-specific, 32 generic)

**Mutation variants produced**:
- Converted parameterized XPath to f-string injection
- [CWE-643] XPath string concat injection
- [CWE-643] XPath %-format injection
- [Generic] Removed security guard (simple_guard)

---

## LOGINJECT

**Description**: Removes log sanitization (newline stripping, encoding), enabling log injection/forging.
**Target CWEs**: CWE-117
**Total mutants**: 62 (60 CWE-specific, 2 generic)

**Mutation variants produced**:
- Removed newline sanitization from log input
- [CWE-117] Used unsanitized username in log
- [CWE-117] Used unsanitized action in log
- [CWE-117] Removed \n sanitization only

**Example** (CWE-117, Removed newline sanitization from log input):

Secure code:
```python
import logging
logger = logging.getLogger(__name__)
def log_user_activity(username, action):
    """Log user activity with sanitization."""
    safe_user = username.replace('\n', ' ').replace('\r', ' ')
    safe_action = action.replace('\n', ' ').replace('\r', ' ')
    logger.info(f"User {safe_user} performed {safe_action}")
```

Mutant code:
```python
import logging
logger = logging.getLogger(__name__)
def log_user_activity(username, action):
    """Log user activity with sanitization."""
    safe_user = username
    safe_action = action
    logger.info(f"User {safe_user} performed {safe_action}")
```

---

## MISSINGAUTH

**Description**: Removes authorization checks (role verification, ownership validation), allowing unauthorized access.
**Target CWEs**: CWE-862, CWE-863
**Total mutants**: 83 (76 CWE-specific, 7 generic)

**Mutation variants produced**:
- Bypassed authorization check
- Removed PermissionError authorization check
- Dead user/is_admin check (pass instead of raise)
- Bypassed .is_admin check with True

**Example** (CWE-862, Bypassed authorization check):

Secure code:
```python
def delete_account_auth(user_id, current_user, is_admin=False):
    """Delete account with authorization."""
    if current_user.id != user_id and not is_admin:
        raise PermissionError("Unauthorized")
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return "Account deleted"
```

Mutant code:
```python
def delete_account_auth(user_id, current_user, is_admin=False):
    """Delete account with authorization."""
    if False:
        raise PermissionError("Unauthorized")
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return "Account deleted"
```

---

## NOCERTVALID

**Description**: Disables SSL/TLS certificate validation (verify=False), enabling MITM attacks.
**Target CWEs**: CWE-295
**Total mutants**: 60 (57 CWE-specific, 3 generic)

**Mutation variants produced**:
- Disabled SSL certificate verification
- [CWE-295] Removed verify parameter
- [CWE-295] Set verify to invalid cert path
- [CWE-295] verify=False + suppressed warnings

**Example** (CWE-295, Disabled SSL certificate verification):

Secure code:
```python
import requests
def secure_request(url):
    """Make HTTPS request with certificate verification."""
    return requests.get(url, verify=True).text
```

Mutant code:
```python
import requests
def secure_request(url):
    """Make HTTPS request with certificate verification."""
    return requests.get(url, verify=False).text
```

---

## OPENREDIRECT

**Description**: Removes URL validation on redirects, allowing redirection to attacker-controlled sites.
**Target CWEs**: CWE-601
**Total mutants**: 63 (44 CWE-specific, 19 generic)

**Mutation variants produced**:
- Removed scheme validation (open redirect)
- Bypassed netloc domain check
- Dead netloc domain check (pass instead of raise)
- Dead scheme validation check (pass instead of raise)

**Example** (CWE-601, Removed scheme validation (open redirect)):

Secure code:
```python
from urllib.parse import urlparse
def redirect_after_login(next_url):
    """Redirect user after login with validation."""
    parsed = urlparse(next_url)
    # Only allow relative URLs or same-domain
    if parsed.netloc and parsed.netloc != "example.com":
        raise ValueError("Invalid redirect URL")
    if parsed.scheme and parsed.scheme not in ('http', 'https'):
        raise ValueError("Invalid URL scheme")
    return f"Location: {next_url}"
```

Mutant code:
```python
from urllib.parse import urlparse
def redirect_after_login(next_url):
    """Redirect user after login with validation."""
    parsed = urlparse(next_url)
    # Only allow relative URLs or same-domain
    if parsed.netloc and parsed.netloc != "example.com":
        raise ValueError("Invalid redirect URL")
        return f"Location: {next_url}"
```

---

## PATHCONCAT

**Description**: Replaces safe path resolution (os.path.join + realpath checks) with unsafe string concatenation.
**Target CWEs**: CWE-22
**Total mutants**: 87 (60 CWE-specific, 27 generic)

**Mutation variants produced**:
- [Easy] Removed .resolve() - path not canonicalized
- [Medium] Replaced .resolve() with .absolute() (no symlink resolution)
- [Medium] Replaced (base / filename) with f-string (no canonicalization)
- [Easy] Dead path prefix check (pass instead of raise)

**Example** (CWE-22, [Easy] Removed .resolve() - path not canonicalized):

Secure code:
```python
from pathlib import Path
def read_file(filename):
    """Read file with path validation."""
    base = Path("/uploads").resolve()
    target = (base / filename).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal detected")
    with open(target) as f:
        return f.read()
```

Mutant code:
```python
from pathlib import Path
def read_file(filename):
    """Read file with path validation."""
    base = Path("/uploads")
    target = (base / filename)
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal detected")
    with open(target) as f:
        return f.read()
```

---

## PSQLI

**Description**: Converts parameterized SQL queries to string concatenation/interpolation, introducing SQL injection.
**Target CWEs**: CWE-89
**Total mutants**: 80 (80 CWE-specific, 0 generic)

**Mutation variants produced**:
- [Variant 1] f-string: query 'query'
- [Variant 2] Concatenation: query 'query'
- [Variant 3] % format: query 'query'
- [Variant 4] .format(): query 'query'

**Example** (CWE-89, [Variant 1] f-string: query 'query'):

Secure code:
```python
def get_user_by_id(user_id):
    """Get user by ID using parameterized query."""
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
```

Mutant code:
```python
def get_user_by_id(user_id):
    """Get user by ID using parameterized query."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
```

---

## REGEXDOS

**Description**: Introduces vulnerable regex patterns susceptible to catastrophic backtracking (ReDoS).
**Target CWEs**: CWE-400
**Total mutants**: 24 (24 CWE-specific, 0 generic)

**Mutation variants produced**:
- Removed read size limit (unlimited read)
- Bypassed size limit check
- Bypassed size limit check
- Removed read size limit (unlimited read)

**Example** (CWE-400, Removed read size limit (unlimited read)):

Secure code:
```python
MAX_SIZE = 10 * 1024 * 1024  # 10MB
def process_upload(file_data):
    """Process upload with size limit."""
    content = file_data.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        raise ValueError("File too large")
    return content
```

Mutant code:
```python
MAX_SIZE = 10 * 1024 * 1024  # 10MB
def process_upload(file_data):
    """Process upload with size limit."""
    content = file_data.read()
    if len(content) > MAX_SIZE:
        raise ValueError("File too large")
    return content
```

---

## RENCRYPT

**Description**: Removes or weakens encryption of sensitive data in transit or at rest.
**Target CWEs**: CWE-319
**Total mutants**: 90 (82 CWE-specific, 8 generic)

**Mutation variants produced**:
- Changed verify=True to verify=False
- Replaced https with http
- [CWE-319] Removed verify parameter
- [CWE-319] HTTP + no cert verification

**Example** (CWE-319, Changed verify=True to verify=False):

Secure code:
```python
import requests
def send_to_api(endpoint, data):
    """Send data to API over HTTPS."""
    url = f"https://api.example.com/{endpoint}"
    return requests.post(url, json=data, verify=True).json()
```

Mutant code:
```python
import requests
def send_to_api(endpoint, data):
    """Send data to API over HTTPS."""
    url = f"https://api.example.com/{endpoint}"
    return requests.post(url, json=data, verify=False).json()
```

---

## RMAUTH

**Description**: Removes authentication checks (is_authenticated, verify_token), allowing unauthenticated access.
**Target CWEs**: CWE-306, CWE-862
**Total mutants**: 105 (21 CWE-specific, 84 generic)

**Mutation variants produced**:
- Replaced request.user.is_authenticated with True
- [Generic] Dead security check (simple_guard, pass instead of raise)
- [Generic] Bypassed security condition (simple_guard)
- [Generic] Removed security guard (simple_guard)

**Example** (CWE-306, Replaced request.user.is_authenticated with True):

Secure code:
```python
def admin_delete_user(request, user_id):
    """Delete user with auth check."""
    if not request.user or not request.user.is_authenticated:
        raise PermissionError("Authentication required")
    if not request.user.is_admin:
        raise PermissionError("Admin access required")
    return db.delete_user(user_id)
```

Mutant code:
```python
def admin_delete_user(request, user_id):
    """Delete user with auth check."""
    if not request.user or not True:
        raise PermissionError("Authentication required")
    if not request.user.is_admin:
        raise PermissionError("Admin access required")
    return db.delete_user(user_id)
```

---

## RVALID

**Description**: Removes input validation checks (sanitization, escaping, filtering), allowing unsanitized input through.
**Target CWEs**: CWE-20, CWE-74, CWE-79, CWE-915
**Total mutants**: 151 (122 CWE-specific, 29 generic)

**Mutation variants produced**:
- Removed html.escape() validation
- [CWE-79] Removed escape (XSS)
- [CWE-79] Removed html.escape assignment (uses raw input)
- [CWE-79] Replaced html.escape with str (no escaping)

**Example** (CWE-79, Removed html.escape() validation):

Secure code:
```python
import html
def render_greeting(name):
    """Render greeting with HTML escaping."""
    safe_name = html.escape(name)
    return f"<h1>Hello, {safe_name}!</h1>"
```

Mutant code:
```python
import html
def render_greeting(name):
    """Render greeting with HTML escaping."""
    safe_name = name
    return f"<h1>Hello, {safe_name}!</h1>"
```

---

## SSRF

**Description**: Removes URL validation (hostname checks, scheme restrictions), allowing internal network requests.
**Target CWEs**: CWE-918
**Total mutants**: 97 (28 CWE-specific, 69 generic)

**Mutation variants produced**:
- [Easy] Removed hostname prefix check from compound condition
- [Easy] Emptied blocklist (all hosts allowed)
- [Easy] Dead hostname blocklist (pass instead of raise)
- [Generic] Bypassed security condition (simple_guard)

**Example** (CWE-918, [Easy] Removed hostname prefix check from compound condition):

Secure code:
```python
import requests
from urllib.parse import urlparse
BLOCKED_HOSTS = ['localhost', '127.0.0.1', '169.254.169.254', '0.0.0.0']
def fetch_url(url):
    """Fetch URL with SSRF protection."""
    parsed = urlparse(url)
    if parsed.hostname in BLOCKED_HOSTS or parsed.hostname.startswith('192.168.'):
        raise ValueError("Access to internal hosts blocked")
    return requests.get(url, timeout=10).text
```

Mutant code:
```python
import requests
from urllib.parse import urlparse
BLOCKED_HOSTS = ['localhost', '127.0.0.1', '169.254.169.254', '0.0.0.0']
def fetch_url(url):
    """Fetch URL with SSRF protection."""
    parsed = urlparse(url)
    if parsed.hostname in BLOCKED_HOSTS:
        raise ValueError("Access to internal hosts blocked")
    return requests.get(url, timeout=10).text
```

---

## WEAKCRYPTO

**Description**: Replaces strong cryptographic algorithms (SHA-256, bcrypt) with weak ones (MD5, SHA-1).
**Target CWEs**: CWE-327, CWE-328
**Total mutants**: 128 (107 CWE-specific, 21 generic)

**Mutation variants produced**:
- sha256 → md5
- sha256 → sha1
- [Line] Removed line 8: v_c9449f_input = hashlib.sha256(v_bd148b_entry).hexdigest()
- [CWE-327] Used hashlib.new('md5') instead of sha256

**Example** (CWE-327, sha256 → md5):

Secure code:
```python
import hashlib


def validate_d145ac(v_bd148b_entry, v_3ec660_record):
    '''
    Return true if the v_bd148b_entry matches the v_3ec660_record.
    '''
    v_c9449f_input = hashlib.sha256(v_bd148b_entry).hexdigest()
    return v_c9449f_input == v_3ec660_record
```

Mutant code:
```python
import hashlib


def validate_d145ac(v_bd148b_entry, v_3ec660_record):
    '''
    Return true if the v_bd148b_entry matches the v_3ec660_record.
    '''
    v_c9449f_input = hashlib.md5(v_bd148b_entry).hexdigest()
    return v_c9449f_input == v_3ec660_record
```

---

## WEAKKEY

**Description**: Reduces cryptographic key sizes below recommended minimums (e.g., RSA 512 instead of 2048).
**Target CWEs**: CWE-326
**Total mutants**: 47 (46 CWE-specific, 1 generic)

**Mutation variants produced**:
- Reduced RSA.generate key from 2048 to 512 bits
- [CWE-326] Reduced RSA.generate key to 1024
- [CWE-326] Reduced RSA.generate key to 768
- [CWE-326] Reduced RSA.generate key to 256

**Example** (CWE-326, Reduced RSA.generate key from 2048 to 512 bits):

Secure code:
```python
from Crypto.PublicKey import RSA

def add_private_key() -> str:
    """
    Generate a private RSA key, export it using the PEM format, and return it as a string.

    Returns:
        str: The RSA private key in PEM format.
    """
    serial = RSA.generate(2048)
    return serial.export_key().decode('utf-8')
```

Mutant code:
```python
from Crypto.PublicKey import RSA

def add_private_key() -> str:
    """
    Generate a private RSA key, export it using the PEM format, and return it as a string.

    Returns:
        str: The RSA private key in PEM format.
    """
    serial = RSA.generate(512)
    return serial.export_key().decode('utf-8')
```

---

## WEAKPERM

**Description**: Weakens file permissions (e.g., 0o600 to 0o777), making sensitive files world-readable.
**Target CWEs**: CWE-732
**Total mutants**: 60 (36 CWE-specific, 24 generic)

**Mutation variants produced**:
- Weakened file permissions 0o600 → 0o777
- [CWE-732] Weakened permissions 0o600→0o666
- [CWE-732] Weakened permissions 0o600→0o644
- [Line] Changed permissions to 0o711

**Example** (CWE-732, Weakened file permissions 0o600 → 0o777):

Secure code:
```python
import json
import os
def save_config(config, filepath):
    """Save config with restricted permissions."""
    fd = os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(config, f)
```

Mutant code:
```python
import json
import os
def save_config(config, filepath):
    """Save config with restricted permissions."""
    fd = os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o777)
    with os.fdopen(fd, 'w') as f:
        json.dump(config, f)
```

---

## WEAKRANDOM

**Description**: Replaces cryptographic random (secrets, os.urandom) with predictable random (random module).
**Target CWEs**: CWE-338
**Total mutants**: 45 (44 CWE-specific, 1 generic)

**Mutation variants produced**:
- Replaced secrets.token_urlsafe with weak random
- Replaced secrets.token_urlsafe with predictable constant
- [CWE-338] Replaced secrets.token_urlsafe with random
- [CWE-338] Replaced secrets.token_urlsafe with predictable

**Example** (CWE-338, Replaced secrets.token_urlsafe with weak random):

Secure code:
```python
import secrets
def generate_api_key(prefix="ak"):
    """Generate cryptographically secure API key."""
    key = secrets.token_urlsafe(24)
    return f"{prefix}_{key}"
```

Mutant code:
```python
import base64
import random
import secrets
def generate_api_key(prefix="ak"):
    """Generate cryptographically secure API key."""
    key = base64.urlsafe_b64encode(random.randbytes(24)).rstrip(b'=').decode()
    return f"{prefix}_{key}"
```

---

## XXE

**Description**: Replaces safe XML parsing (defusedxml) with standard xml.etree that allows entity expansion.
**Target CWEs**: CWE-611
**Total mutants**: 56 (50 CWE-specific, 6 generic)

**Mutation variants produced**:
- Replaced defusedxml with standard xml library
- [CWE-611] Replaced defusedxml with lxml.etree (no restrictions)
- [CWE-611] lxml with resolve_entities=True
- [CWE-611] Replaced defusedxml with vulnerable minidom

**Example** (CWE-611, Replaced defusedxml with standard xml library):

Secure code:
```python
import defusedxml.ElementTree as ET
def parse_xml(xml_string):
    """Parse XML safely."""
    return ET.fromstring(xml_string)
```

Mutant code:
```python
import xml.etree.ElementTree as ET
def parse_xml(xml_string):
    """Parse XML safely."""
    return ET.fromstring(xml_string)
```

---
