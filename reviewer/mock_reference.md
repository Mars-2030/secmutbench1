# Mock Environment Reference — SecMutBench v2.8.0

This document describes all mock objects used in the SecMutBench test execution sandbox. Tests run in an isolated subprocess where these mocks replace real modules, allowing safe execution while tracking security-relevant behavior.

**Key principle:** Mocks are injected into `builtins` — they are available as free variables without `import` statements. The function under test is also already defined in the namespace.

---

## Summary Table

| Mock | Builtin Names | Primary CWEs | Key Security Attribute | Detection Pattern |
|------|--------------|--------------|----------------------|-------------------|
| MockDatabase | `db`, `mock_db`, `database` | CWE-89 | `last_params` | `assert db.last_params is not None` |
| MockSubprocess | `subprocess`, `mock_subprocess` | CWE-78 | `injection_detected` | `assert not subprocess.injection_detected` |
| MockHTTPClient | `requests`, `http_client`, `mock_http` | CWE-918 | `ssrf_attempted` | `assert not requests.ssrf_attempted` |
| MockCrypto | `hashlib`, `mock_crypto` | CWE-327/328 | `weak_algorithm_used` | `assert not hashlib.weak_algorithm_used` |
| MockEnvironment | `env`, `mock_env`, `os_environ` | CWE-798 | `access_log` | `assert len(env.access_log) > 0` |
| MockPickle | `pickle`, `mock_pickle` | CWE-502 | `unsafe_load_called` | `assert not pickle.unsafe_load_called` |
| MockYAML | `yaml`, `mock_yaml` | CWE-502 | `unsafe_load_called` | `assert not yaml.unsafe_load_called` |
| MockMarshal | `marshal`, `mock_marshal` | CWE-502 | `unsafe_load_called` | `assert not marshal.unsafe_load_called` |
| MockEval | `mock_eval` | CWE-94/95 | `unsafe_eval_called` | `assert not mock_eval.unsafe_eval_called` |
| MockRandom | `random`, `mock_random` | CWE-338 | `weak_prng_used` | `assert not mock_random.weak_prng_used` |
| MockSecrets | `secrets`, `mock_secrets` | CWE-338 | `call_log` | `assert mock_random.secure_prng_used` |
| MockAuthenticator | `auth`, `authenticator`, `mock_auth` | CWE-287/306 | `failed_attempts` | `assert raises PermissionError` |
| MockBcrypt | `bcrypt` | CWE-327/287 | `hash_called` | `assert bcrypt.hash_called` |
| MockFileSystem | `fs`, `mock_fs`, `filesystem` | CWE-22 | `last_path` | `assert raises ValueError for "../"` |
| MockFlask | `flask`, `Flask` | CWE-306/319/352 | (framework) | (request/session mocking) |
| MockJWT | `jwt` | CWE-287/347 | `verify_signature` | `assert jwt.decode_called` |
| MockMySQL | `mysql` | CWE-798 | `last_password` | `assert mysql.last_password != "hardcoded"` |
| MockXMLParser | `xml_parser`, `mock_xml` | CWE-611 | `external_entities_resolved` | `assert not xml_parser.external_entities_resolved` |

**Standard libs also available:** `os` (SafeOS wrapper), `sys`, `re`, `json`, `html`, `base64`, `ast`, `inspect`, `pathlib`, `urllib.parse`, `logging`, `hashlib` (mocked).

---

## MockDatabase

**File:** `evaluation/mocks/mock_database.py`
**Builtin names:** `db`, `mock_db`, `database`
**CWEs:** CWE-89 (SQL Injection)

### Purpose

Replaces database connections. Tracks whether queries use parameterized statements (safe) or string interpolation (vulnerable to SQL injection).

### Security-Tracking Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_query` | `str \| None` | The last executed SQL query string |
| `last_params` | `tuple \| None` | Parameters if parameterized; **`None` if string interpolation used (vulnerable)** |
| `query_count` | `int` | Total number of queries executed |

### Key Methods

| Method | Description |
|--------|-------------|
| `execute(query, params=None)` | Execute SQL query. Returns list of dicts. Sets `last_params` to `None` if no params provided (indicates injection). |
| `cursor()` | Returns cursor with `execute()`, `fetchall()`, `fetchone()` |
| `get_user(username)` | Returns user dict with `password` and `password_hash` fields |
| `reset()` | Reset to initial state with default tables |

### Default Tables

- **users**: 3 users (`alice`, `bob`, `charlie`) with plaintext `password` and bcrypt `password_hash`
- **passwords**, **sessions**, **products**, **orders**, **secrets**

### Injection Detection

The mock detects SQL injection patterns in queries: `' OR '1'='1`, `UNION SELECT`, `'; DROP TABLE`, etc. But the primary detection mechanism for tests is checking `last_params`:

```python
db.reset()
result = get_user_by_id("' OR '1'='1")
assert db.last_params is not None, "SQL injection: query not parameterized"
assert "' OR '1'='1" not in db.last_query, "Payload embedded in query"
```

---

## MockSubprocess

**File:** `evaluation/mocks/mock_subprocess.py`
**Builtin names:** `subprocess`, `mock_subprocess`
**CWEs:** CWE-78 (Command Injection)

### Purpose

Replaces the `subprocess` module. Tracks whether commands use `shell=True` (vulnerable) and whether injection patterns are present in command strings.

### Security-Tracking Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_command` | `str \| list \| None` | The last executed command |
| `last_shell` | `bool` | `True` if `shell=True` was used (vulnerable) |
| `injection_detected` | `bool` | **`True` if shell injection patterns found in command** |
| `dangerous_command_detected` | `bool` | `True` if dangerous commands detected (`rm`, `cat /etc`, `wget`, `nc`, `chmod`, `sudo`, etc.) |
| `last_kwargs` | `dict` | Keyword arguments from last call |

### Injection Patterns Detected (12)

`;`, `&&`, `||`, `|` (pipe), `` ` `` (backticks), `$(`, `\n`, `\r`, `>`, `<`, `>>`, `2>`

### Dangerous Commands Detected (11)

`rm `, `cat /etc`, `wget `, `curl `, `nc `, `ncat `, `/bin/sh`, `/bin/bash`, `chmod `, `chown `, `sudo `

### Key Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `run(args, shell=False, ...)` | `MockCompletedProcess` | Execute command |
| `call(args, shell=False, ...)` | `int` | Execute and return exit code |
| `check_output(args, shell=False, ...)` | `str` | Execute and return stdout |
| `Popen(args, shell=False, ...)` | `MockPopen` | Start process |
| `reset()` | — | Reset all tracking state |

### Constants

`PIPE`, `STDOUT`, `DEVNULL` — subprocess constants, available for use in tests.

### Example Test

```python
subprocess.reset()
result = ping_host("localhost; cat /etc/passwd")
assert subprocess.last_shell == False, "shell=True used (vulnerable)"
assert not subprocess.injection_detected, "Command injection detected"
```

---

## MockHTTPClient

**File:** `evaluation/mocks/mock_http.py`
**Builtin names:** `requests`, `http_client`, `mock_http`
**CWEs:** CWE-918 (SSRF)

### Purpose

Replaces the `requests` library. Tracks whether requests target internal/private network addresses (SSRF).

### Security-Tracking Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_url` | `str \| None` | URL of the last request |
| `last_method` | `str \| None` | HTTP method used (GET, POST, etc.) |
| `last_kwargs` | `dict` | Request kwargs (`data`, `json`, `headers`, `verify`, etc.) |
| `ssrf_attempted` | `bool` | **`True` if internal/private URL accessed** |
| `request_count` | `int` | Total requests made |

### Internal Hosts Detected

`localhost`, `127.0.0.1`, `192.168.*`, `10.*`, `172.16.*`, `169.254.*`

### Predefined Responses

| URL | Response |
|-----|----------|
| `http://api.example.com/data` | `{"status": "ok"}` |
| `http://localhost/admin` | `"admin_secret_data"` |
| `http://169.254.169.254/latest/meta-data/` | `"aws_metadata"` |

### Key Methods

| Method | Description |
|--------|-------------|
| `get(url, **kwargs)` | HTTP GET request |
| `post(url, data=None, json=None, **kwargs)` | HTTP POST request |
| `put()`, `delete()`, `patch()`, `head()` | Other HTTP methods |
| `request(method, url, **kwargs)` | Generic request |
| `reset()` | Reset all tracking state |

### MockHTTPResponse

Returned by all request methods:
- `status_code` (int), `content` (str), `text` (str), `cookies` (dict), `headers` (dict)
- `json()` — parse response as JSON
- `raise_for_status()` — raise for 4xx/5xx

### Example Test

```python
requests.reset()
result = fetch_url("http://169.254.169.254/latest/meta-data/")
assert not requests.ssrf_attempted, "SSRF: accessed internal URL"
```

---

## MockCrypto

**File:** `evaluation/mocks/mock_crypto.py`
**Builtin names:** `hashlib`, `mock_crypto`
**CWEs:** CWE-327 (Weak Cryptographic Algorithm), CWE-328 (Reversible One-Way Hash)

### Purpose

Replaces the `hashlib` module. Tracks whether weak cryptographic algorithms are used instead of strong ones.

### Security-Tracking Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_algorithm` | `str \| None` | Name of the last algorithm used |
| `algorithms_used` | `list[str]` | All algorithms used during test |
| `weak_algorithm_used` | `bool` | **`True` if any weak algorithm used** |
| `strong_algorithm_used` | `bool` | `True` if any strong algorithm used |

### Algorithm Classification

| Classification | Algorithms |
|---------------|------------|
| **Weak** | md5, md4, md2, sha1, des, 3des, rc4, rc2, blowfish |
| **Strong** | sha256, sha384, sha512, sha3_*, blake2b, blake2s, bcrypt, scrypt, argon2, aes, chacha20, pbkdf2 |

### Key Methods

| Method | Classification | Description |
|--------|---------------|-------------|
| `md5(data)` | WEAK | Returns `MockHashObject` |
| `sha1(data)` | WEAK | Returns `MockHashObject` |
| `sha256(data)` | STRONG | Returns `MockHashObject` |
| `sha384(data)`, `sha512(data)` | STRONG | Returns `MockHashObject` |
| `blake2b(data)`, `blake2s(data)` | STRONG | Returns `MockHashObject` |
| `new(name, data)` | varies | Generic hash creation |
| `pbkdf2_hmac(hash_name, password, salt, iterations, dklen)` | STRONG | Key derivation function |
| `scrypt(password, salt, n, r, p, dklen)` | STRONG | Key derivation function |
| `reset()` | — | Reset all tracking state |

### MockHashObject

Returned by hash functions:
- `update(data)`, `digest()` (bytes), `hexdigest()` (str), `copy()`
- `algorithm`, `name`, `digest_size`

### Example Test

```python
hashlib.reset()
result = hash_password("secret123")
assert not hashlib.weak_algorithm_used, f"Weak algorithm {hashlib.last_algorithm} used"
assert hashlib.strong_algorithm_used, "Should use strong algorithm"
```

---

## MockPickle / MockYAML / MockMarshal

**File:** `evaluation/mocks/mock_deserializer.py`
**CWEs:** CWE-502 (Insecure Deserialization)

### MockPickle

**Builtin names:** `pickle`, `mock_pickle`

| Attribute | Type | Description |
|-----------|------|-------------|
| `unsafe_load_called` | `bool` | **`True` if `pickle.loads()` or `pickle.load()` called** |
| `load_count` | `int` | Number of deserialization operations |
| `last_data` | `bytes \| None` | Last data deserialized |
| `operations` | `list[str]` | Operation history |

| Method | Safety | Description |
|--------|--------|-------------|
| `loads(data)` | UNSAFE | Deserialize from bytes |
| `load(file)` | UNSAFE | Deserialize from file |
| `dumps(obj)` | safe | Serialize to bytes |
| `dump(obj, file)` | safe | Serialize to file |
| `reset()` | — | Reset state |

### MockYAML

**Builtin names:** `yaml`, `mock_yaml`

| Attribute | Type | Description |
|-----------|------|-------------|
| `unsafe_load_called` | `bool` | **`True` if `yaml.load()` without SafeLoader** |
| `safe_loader_used` | `bool` | `True` if SafeLoader was used |
| `load_count` | `int` | Number of loads |
| `last_data` | `str \| None` | Last YAML data |
| `operations` | `list[str]` | Operation history |

| Method | Safety | Description |
|--------|--------|-------------|
| `load(data, Loader=None)` | UNSAFE (unless `Loader=SafeLoader`) | Parse YAML |
| `safe_load(data)` | SAFE | Parse YAML safely |
| `safe_load_all(data)` | SAFE | Parse multi-document YAML safely |
| `dump(data)`, `safe_dump(data)` | safe | Serialize to YAML |
| `reset()` | — | Reset state |

**Loader classes available:** `SafeLoader` (secure), `FullLoader`, `UnsafeLoader`, `Loader`

### MockMarshal

**Builtin names:** `marshal`, `mock_marshal`

| Attribute | Type | Description |
|-----------|------|-------------|
| `unsafe_load_called` | `bool` | `True` if `marshal.loads()` or `marshal.load()` called |

### Example Test

```python
pickle.reset()
yaml.reset()
result = deserialize_data(untrusted_data)
assert not pickle.unsafe_load_called, "Insecure: pickle used for untrusted data"
assert not yaml.unsafe_load_called or yaml.safe_loader_used, "Insecure: yaml.load without SafeLoader"
```

---

## MockEnvironment

**File:** `evaluation/mocks/mock_environment.py`
**Builtin names:** `env`, `mock_env`, `os_environ`
**CWEs:** CWE-798 (Hardcoded Credentials)

### Purpose

Replaces `os.environ`. Tracks whether code reads credentials from environment variables (secure) or uses hardcoded values.

### Security-Tracking Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_key` | `str \| None` | Last environment variable accessed |
| `last_default` | `str \| None` | Default value used (if any) |
| `access_log` | `list[str]` | All keys accessed (in order) |
| `sensitive_accessed` | `list[str]` | Sensitive keys accessed (PASSWORD, SECRET, KEY, TOKEN, CREDENTIAL, API_KEY, etc.) |

### Default Variables

| Variable | Value |
|----------|-------|
| `PATH`, `HOME`, `USER`, `SHELL` | Standard OS values |
| `DB_PASSWORD` | `"test_db_password"` |
| `API_KEY` | `"test_api_key_12345"` |
| `SECRET_KEY` | `"test_secret_key"` |
| `AUTH_TOKEN` | `"test_auth_token"` |

### Key Methods

| Method | Description |
|--------|-------------|
| `get(key, default=None)` | Get env var (like `os.environ.get()`) |
| `set(key, value)` | Set env var |
| `__getitem__(key)` / `__setitem__(key, value)` | Dict-like access: `env["KEY"]` |
| `__contains__(key)` | `"KEY" in env` |
| `getenv(key, default)` | Alias for `get()` |
| `reset()` | Reset to defaults |

### MockOS (SafeOS wrapper)

Also injected as `builtins.os`. Wraps the real `os` module:
- **Blocked operations** (raise `PermissionError`): `system`, `popen`, `spawn*`, `exec*`, `fork`, `forkpty`
- **Passed through:** `path.join`, `path.exists`, `getcwd`, `makedirs`, etc.
- `os.environ` returns the `MockEnvironment` instance
- `os.getenv(key)` delegates to `MockEnvironment.get()`

### Example Test

```python
env.reset()
env.set("DB_PASSWORD", "unique_test_value_12345")
result = get_db_password()
assert result == "unique_test_value_12345", "Hardcoded password detected"
assert "DB_PASSWORD" in env.access_log, "Environment not checked"
```

---

## MockEval

**File:** `evaluation/mocks/mock_eval.py`
**Builtin names:** `mock_eval`
**CWEs:** CWE-94 (Code Injection), CWE-95 (Eval Injection)

### Purpose

Tracks use of `eval()`, `exec()`, and `compile()` with untrusted input. Detects dangerous code patterns that indicate injection.

### Security-Tracking Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `unsafe_eval_called` | `bool` | **`True` if `eval()` called** |
| `unsafe_exec_called` | `bool` | **`True` if `exec()` called** |
| `safe_eval_called` | `bool` | `True` if `literal_eval()` called |
| `eval_count` | `int` | Number of eval calls |
| `exec_count` | `int` | Number of exec calls |
| `last_code` | `str \| None` | Last code string passed |
| `injection_detected` | `bool` | **`True` if injection patterns found in code** |
| `operations` | `list[dict]` | Full operation history |

### Injection Patterns Detected (14)

`__import__`, `os.system`, `subprocess`, `open(`, `exec(`, `eval(`, `__class__`, `__bases__`, `__subclasses__`, `__globals__`, `__builtins__`, `getattr(`, `setattr(`, `compile(`

### Key Methods

| Method | Safety | Description |
|--------|--------|-------------|
| `eval(code, globals, locals)` | UNSAFE | Execute expression |
| `exec(code, globals, locals)` | UNSAFE | Execute statements |
| `literal_eval(code)` | SAFE | Parse literals only (strings, numbers, lists, dicts, tuples, booleans, None) |
| `compile(source, filename, mode)` | varies | Compile code |
| `is_safe_expression(code)` | — | Check if expression is safe |
| `reset()` | — | Reset all state |

### Example Test

```python
mock_eval.reset()
result = process_expression(user_input)
assert not mock_eval.unsafe_eval_called, "Code injection: eval() used on user input"
assert not mock_eval.injection_detected, "Dangerous patterns in evaluated code"
```

---

## MockRandom / MockSecrets

**File:** `evaluation/mocks/mock_random.py`
**CWEs:** CWE-338 (Weak PRNG)

### MockRandom

**Builtin names:** `random`, `mock_random`

Replaces the `random` module. Any call marks `weak_prng_used = True`.

| Attribute | Type | Description |
|-----------|------|-------------|
| `weak_prng_used` | `bool` | **`True` if any `random` module function called** |
| `secure_prng_used` | `bool` | `True` if `secrets` module used (set by MockSecrets) |
| `call_log` | `list[str]` | Operation history |

| Method | Classification |
|--------|---------------|
| `random()`, `randint(a, b)`, `randrange(*args)` | WEAK |
| `choice(seq)`, `choices(...)`, `shuffle(x)`, `sample(population, k)` | WEAK |
| `getrandbits(k)`, `uniform(a, b)`, `seed(a)` | WEAK |

### MockSecrets

**Builtin names:** `secrets`, `mock_secrets`

Replaces the `secrets` module. Calls set `mock_random.secure_prng_used = True`.

| Method | Classification |
|--------|---------------|
| `token_bytes(nbytes)`, `token_hex(nbytes)`, `token_urlsafe(nbytes)` | SECURE |
| `randbelow(n)`, `choice(seq)`, `randbits(k)` | SECURE |

### Example Test

```python
mock_random.reset()
result = generate_token()
assert not mock_random.weak_prng_used, "Weak PRNG used for security-sensitive operation"
assert mock_random.secure_prng_used, "Should use secrets or os.urandom"
```

---

## MockAuthenticator

**File:** `evaluation/mocks/mock_auth.py`
**Builtin names:** `auth`, `authenticator`, `mock_auth`
**CWEs:** CWE-287 (Improper Authentication), CWE-306 (Missing Authentication)

### Purpose

Provides authentication/authorization testing infrastructure. Tests can verify that code properly checks credentials before granting access.

### Security-Tracking Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_username` | `str \| None` | Last username attempted |
| `last_password` | `str \| None` | Last password attempted |
| `last_token` | `str \| None` | Last token checked |
| `auth_attempts` | `int` | Total authentication attempts |
| `failed_attempts` | `int` | Failed authentication attempts |

### Valid Credentials

| Username | Password (MD5 hash) | Role |
|----------|---------------------|------|
| `admin` | `5f4dcc3b5aa765d61d8327deb882cf99` | `admin` |
| `user1` | `ee11cbb19052e40b07aac0ca060c23ee` | `user` |

### Valid Sessions/Tokens

- Session: `valid_session_token_123` → user `admin`, expires `2099-12-31`
- JWT: `valid_jwt_token` → user `admin`, exp `9999999999`

### Key Methods

| Method | Description |
|--------|-------------|
| `verify_password(username, password)` | Verify credentials (MD5 check) |
| `verify_session(session_token)` | Verify session token |
| `verify_jwt(token)` | Verify JWT token |
| `create_session(username)` | Create session token |
| `get_user_role(username)` | Get user's role |
| `reset()` | Reset state |

---

## MockBcrypt

**File:** `evaluation/mocks/mock_bcrypt.py`
**Builtin names:** `bcrypt`
**CWEs:** CWE-327 (Weak Crypto), CWE-287 (Authentication)

### Purpose

Replaces the `bcrypt` library. Provides password hashing/verification without the real C library dependency.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `hash_called` | `bool` | `True` if `hashpw()` called |
| `check_called` | `bool` | `True` if `checkpw()` called |
| `last_password` | `bytes \| None` | Last password hashed |

### Key Methods

| Method | Description |
|--------|-------------|
| `hashpw(password, salt)` | Hash password (returns `$2b$` prefixed hash) |
| `gensalt(rounds=12)` | Generate salt |
| `checkpw(password, hashed)` | Verify password against hash |
| `reset()` | Reset state |

### Known Test Pairs

| Password | Hash |
|----------|------|
| `test_password_alice` | `$2b$12$LQv3c1yqBWVHxkd0LHAkCOtest_alice_hash` |
| `test_password_bob` | `$2b$12$LQv3c1yqBWVHxkd0LHAkCOtest_bob_hash` |
| `test_password_charlie` | `$2b$12$LQv3c1yqBWVHxkd0LHAkCOtest_charlie_hash` |
| `correct_password` | `$2b$12$LQv3c1yqBWVHxkd0LHAkCO` |

---

## MockFileSystem

**File:** `evaluation/mocks/mock_filesystem.py`
**Builtin names:** `fs`, `mock_fs`, `filesystem`
**CWEs:** CWE-22 (Path Traversal)

### Purpose

Provides an in-memory filesystem for testing path traversal protections. Contains files in an allowed base directory and sensitive files outside it.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_path` | `str \| None` | Last file path accessed |
| `base_dir` | `str` | Allowed base directory (default: `/var/data`) |

### Default Files

| Path | Content |
|------|---------|
| `/var/data/file1.txt` | `"file1 content"` |
| `/var/data/file2.txt` | `"file2 content"` |
| `/var/data/test.txt` | `"test content"` |
| `/var/data/sub/file.txt` | `"sub file content"` |
| `/etc/passwd` | `"root:x:0:0:root:/root:/bin/bash"` |
| `/app/secrets/api_key.txt` | `"secret_key_12345"` |

### Key Methods

| Method | Description |
|--------|-------------|
| `read_file(path)` | Read file contents (normalizes path). Returns content or `None`. |
| `write_file(path, content)` | Write file to filesystem |
| `delete_file(path)` | Delete file |
| `file_exists(path)` | Check if file exists |
| `list_files(directory)` | List files in directory |
| `reset()` | Reset to default files |

### Example Test

```python
fs.reset()
try:
    result = read_user_file("../../etc/passwd")
    pytest.fail("Path traversal should have been rejected")
except ValueError:
    pass  # Secure code rejected traversal
```

---

## MockXMLParser

**File:** `evaluation/mocks/mock_xml.py`
**Builtin names:** `xml_parser`, `mock_xml`
**CWEs:** CWE-611 (XXE — XML External Entity)

### Purpose

Tracks whether XML parsing resolves external entities (vulnerable to XXE attacks).

### Security-Tracking Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_xml` | `str \| None` | Last XML string parsed |
| `external_entities_resolved` | `bool` | **`True` if XXE patterns found in XML** |
| `dtd_processed` | `bool` | `True` if DTD processing detected |

### XXE Patterns Detected (7)

`<!ENTITY`, `<!DOCTYPE`, `SYSTEM`, `file://`, `http://`, `expect://`, `php://`

### Key Methods

| Method | Safety | Description |
|--------|--------|-------------|
| `parse_unsafe(xml_string)` | VULNERABLE | Parses XML and resolves external entities |
| `parse_safe(xml_string)` | SAFE | Parses XML with XXE protection enabled |
| `has_external_entities(xml_string)` | — | Check if XML contains external entity patterns |
| `reset()` | — | Reset state |

### Example Test

```python
xml_parser.reset()
malicious_xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
result = parse_xml(malicious_xml)
assert not xml_parser.external_entities_resolved, "XXE: external entities resolved"
```

---

## MockFlask

**File:** `evaluation/mocks/mock_flask.py`
**Builtin names:** `flask`, `Flask`
**CWEs:** CWE-306 (Missing Auth), CWE-319 (Cleartext Transmission), CWE-352 (CSRF)

### Purpose

Provides Flask web framework mocks for testing web application security patterns.

### Available Objects

| Object | Type | Description |
|--------|------|-------------|
| `request` | `MockRequest` | HTTP request with `method`, `form`, `args`, `json`, `cookies`, `headers`, `is_secure` |
| `session` | `MockSession` | Session dict with `modified`, `permanent` |
| `g` | `MockG` | Request-scoped data |
| `Flask` | `MockFlask` | App object with `route()`, `before_request()`, `run()` |
| `abort` | function | `abort(status_code, description)` |
| `redirect` | function | `redirect(location, code=302)` |
| `url_for` | function | `url_for(endpoint, **values)` |
| `render_template` | function | `render_template(template, **context)` |
| `jsonify` | function | `jsonify(*args, **kwargs)` |
| `login_required` | decorator | `@login_required` |
| `make_response` | function | `make_response(*args)` |
| `current_user` | object | Current user object |

### MockRequest Attributes

- `method` (str): HTTP method (default `"GET"`)
- `form` (dict): Form data
- `args` (dict): Query parameters
- `json` (dict): JSON body
- `cookies` (dict): Request cookies
- `headers` (dict): Request headers
- `is_secure` (bool): `False` for HTTP, `True` for HTTPS

---

## MockJWT

**File:** `evaluation/mocks/mock_jwt.py`
**Builtin names:** `jwt`
**CWEs:** CWE-287 (Authentication), CWE-347 (Missing Signature Verification)

### Purpose

Replaces the `PyJWT` library. Tracks JWT encode/decode operations and signature verification.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_token` | `str \| None` | Last token decoded |
| `last_secret` | `str \| None` | Secret used for decoding |
| `last_algorithms` | `list \| None` | Algorithms specified |
| `decode_called` | `bool` | `True` if `decode()` called |
| `verify_signature` | `bool` | Whether signature verification was enabled |

### Key Methods

| Method | Description |
|--------|-------------|
| `encode(payload, secret, algorithm="HS256")` | Create JWT token |
| `decode(token, key=None, algorithms=None, options=None)` | Decode JWT (raises `InvalidTokenError` for invalid tokens) |
| `get_unverified_header(token)` | Get JWT header without verification |
| `reset()` | Reset state |

### Valid Tokens

- `valid_token_123` → payload: `{"user": "admin", "exp": 9999999999}`

### Exception Classes

`InvalidTokenError`, `ExpiredSignatureError`, `DecodeError`

---

## MockMySQL

**File:** `evaluation/mocks/mock_mysql.py`
**Builtin names:** `mysql`, `mysql.connector`
**CWEs:** CWE-798 (Hardcoded Credentials)

### Purpose

Replaces `mysql.connector`. Tracks database connection parameters to detect hardcoded credentials.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `last_host` | `str \| None` | Last connection host |
| `last_user` | `str \| None` | Last connection username |
| `last_password` | `str \| None` | Last connection password |
| `last_database` | `str \| None` | Last connection database |
| `connect_called` | `bool` | `True` if `connect()` called |

### Key Methods

| Method | Description |
|--------|-------------|
| `connect(host, user, password, database, **kwargs)` | Create connection (returns `MockConnection`) |
| `reset()` | Reset state |

### MockConnection

- `cursor()` → `MockCursor` (with `execute()`, `fetchone()`, `fetchall()`)
- `close()`, `commit()`, `rollback()`

---

## Injection Mechanism

All mocks are injected via `evaluation/conftest_template.py`, which is written into each test subprocess's temporary directory as `conftest.py`.

### Injection steps:

1. **Instance creation** (lines 76–135): Shared singleton instances of each mock are created
2. **Builtins injection** (lines 145–227): Mocks are set on `builtins`, making them available as free variables without imports
3. **sys.modules patching** (lines 644–744): `import hashlib`, `import pickle`, etc. resolve to mock modules instead of real ones
4. **SafeOS wrapper** (line 213): `builtins.os` is replaced with `SafeOS` that blocks dangerous operations
5. **Security tracking** (lines 784–799): Before each test, security tracking is reset; after each test, accessed security attributes are recorded

### All `reset()` calls

Every mock supports `reset()` to clear its tracking state. Tests should call `mock.reset()` at the start to ensure clean state. The conftest also resets security tracking automatically before each test via the `ResultCollector` pytest plugin.

---

## Source Inspection Alternative

For CWEs where mock-based outcome testing is insufficient (e.g., detecting `defusedxml` imports or `verify=True` in source code), tests can use **source inspection**:

```python
import inspect

# Get the function's source code
source = inspect.getsource(function_name)

# Get the entire module's source (includes imports)
module = inspect.getmodule(function_name)
module_source = inspect.getsource(module)

# Check for secure patterns
assert "defusedxml" in module_source, "Should use defusedxml for safe XML parsing"
assert "verify=True" in source or "verify=False" not in source, "SSL verification disabled"
```

This is particularly useful for:
- **CWE-611**: Detecting `defusedxml` vs `xml.etree` imports
- **CWE-295**: Detecting `verify=False` in source
- **CWE-319**: Detecting `http://` vs `https://` in URLs
- **CWE-327**: Detecting algorithm names in source when `hashlib.new()` is used
