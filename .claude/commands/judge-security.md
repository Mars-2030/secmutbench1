You are an expert security engineer evaluating LLM-generated security tests. Your task is to assess whether the tests effectively target the specified vulnerability type.

## Input

The user will provide a path to a results JSON file. If no path is given, find the most recent `baseline_results_*.json` file under `results/` (excluding `_judged` files).

## Steps

1. **Load the results file**. It has `results[]` — an array of variant results (e.g., full, no-hint, cwe-only). **Loop over ALL variants.**

2. **For each sample** with non-empty `generated_tests`, evaluate security relevance using the criteria and context below.

3. **For each sample, reason step by step:**
   a. What CWE is this sample about? What does the secure code do?
   b. What attack vectors should a good security test include for this CWE? (See Attack Vectors Reference below)
   c. Does the test use the correct mock objects? (See Mock Environment Reference below)
   d. Are the assertions checking security properties (not just functionality)?
   e. Would this test actually detect if the code were vulnerable?

4. **Score (0-100)** and produce structured output.

5. **Save results** to `{original_stem}_judged_security.json` with ALL variants updated. Add per sample:
   ```json
   {
     "judge_security": {
       "model": "claude",
       "score": 0.85,
       "cwe_addressed": true,
       "attack_vectors_tested": ["SQL tautology OR 1=1", "UNION SELECT"],
       "security_properties_checked": ["parameterized queries", "input sanitization"],
       "reasoning": "Tests correctly use db.last_params to verify parameterized queries and include multiple realistic SQL injection payloads. However, missing blind injection and stacked query tests.",
       "confidence": 0.90
     }
   }
   ```

6. **Print summary** per variant and a cross-variant comparison table.

## Scoring Guidelines

- **90-100 Excellent**: Targets the CWE with multiple realistic payloads, uses correct mocks, assertions verify security properties
- **70-89 Good**: Targets CWE but misses some attack vectors or has some weak assertions
- **50-69 Fair**: Shows security awareness but mostly functional — few attack payloads, generic assertions
- **30-49 Poor**: Barely touches security — tests check return values, not security properties
- **0-29 Irrelevant**: No security value — `assert True`, `assert result is not None`, never calls target

## Mock Environment Reference

Tests run in a sandboxed environment with these mock objects (already available, no imports needed):

**CWE-89 SQL Injection — MockDatabase:**
- `db.execute(query, params=None)`: Execute query
- `db.last_query`: Last SQL query string
- `db.last_params`: Tuple of params if parameterized, **None if vulnerable (string interpolation)**
- `db.reset()`: Reset state
- **DETECTION**: `assert db.last_params is not None`

**CWE-78 Command Injection — MockSubprocess:**
- `subprocess.run(args, shell=False, ...)`
- `subprocess.last_command`, `subprocess.last_shell`
- `subprocess.injection_detected`: **True if shell injection patterns found**
- **DETECTION**: `assert not subprocess.injection_detected`

**CWE-22 Path Traversal — MockFileSystem:**
- `fs.read_file(path)`, `fs.file_exists(path)`, `fs.base_dir`
- **DETECTION**: `pytest.raises(ValueError)` or `pytest.raises(PermissionError)` for `../` paths

**CWE-327/328 Weak Crypto — MockCrypto (as hashlib):**
- `hashlib.weak_algorithm_used`: **True if MD5, SHA1, DES used**
- `hashlib.last_algorithm`, `hashlib.reset()`
- **DETECTION**: `assert not hashlib.weak_algorithm_used`

**CWE-502 Insecure Deserialization — MockPickle/MockYAML:**
- `pickle.unsafe_load_called`: **True if pickle.loads/load used**
- `yaml.unsafe_load_called`: **True if yaml.load without SafeLoader**
- **DETECTION**: `assert not pickle.unsafe_load_called`

**CWE-918 SSRF — MockHTTPClient (as requests):**
- `requests.ssrf_attempted`: **True if internal URL accessed**
- `requests.last_url`, `requests.reset()`
- **DETECTION**: `assert not requests.ssrf_attempted`

**CWE-611 XXE — MockXMLParser:**
- `xml_parser.external_entities_resolved`: **True if XXE patterns found**
- **DETECTION**: `assert not xml_parser.external_entities_resolved`

**CWE-798 Hardcoded Credentials — MockEnvironment:**
- `env.access_log`: List of accessed env var keys
- `env.sensitive_accessed`: Sensitive keys accessed
- **DETECTION**: `assert len(env.access_log) > 0`

**CWE-306/287 Authentication — MockAuthenticator:**
- `auth.login(username, password)`, `auth.auth_attempts`, `auth.failed_attempts`
- **DETECTION**: `pytest.raises(PermissionError)` for unauthenticated access

**CWE-94/95 Code Injection — MockEval:**
- `mock_eval.unsafe_eval_called`: **True if eval() called with untrusted input**
- `mock_eval.injection_detected`: **True if injection patterns found**
- **DETECTION**: `assert not mock_eval.unsafe_eval_called`

## CWE Attack Vectors Reference

**CWE-89 SQL Injection:** `' OR '1'='1`, `UNION SELECT`, `'; DROP TABLE`, `admin'--`, `OR SLEEP(5)--`
**CWE-78 Command Injection:** `; rm -rf /`, `&& cat /etc/passwd`, `| whoami`, `` `id` ``, `$(whoami)`
**CWE-22 Path Traversal:** `../../../etc/passwd`, `%2e%2e%2f`, `%00`, absolute paths
**CWE-79 XSS:** `<script>alert(1)</script>`, `<img onerror=alert(1)>`, `javascript:`, event handlers
**CWE-502 Deserialization:** `pickle.loads(user_input)`, `yaml.load()` without SafeLoader, `__reduce__`
**CWE-918 SSRF:** `http://127.0.0.1`, `http://169.254.169.254`, `file:///etc/passwd`, internal IPs
**CWE-611 XXE:** `<!ENTITY xxe SYSTEM "file:///etc/passwd">`, `<!DOCTYPE>` with external entities
**CWE-601 Open Redirect:** `?next=http://evil.com`, `//attacker.com`, protocol-relative URLs
**CWE-295 Cert Validation:** `verify=False`, `CERT_NONE`, `check_hostname=False`
**CWE-400 ReDoS:** `(a+)+$`, `(.*)*`, nested quantifiers, catastrophic backtracking
**CWE-352 CSRF:** Missing token validation, cross-origin request without token
**CWE-862 Missing Authz:** Access without ownership check, missing role verification
**CWE-306 Missing Auth:** Unauthenticated access to protected resources
**CWE-798 Hardcoded Creds:** `password = "admin123"`, API keys in source, default credentials
**CWE-338 Weak PRNG:** `random.randint()` for security tokens (should use `secrets`)
**CWE-117 Log Injection:** `\n`, `\r`, CRLF in log messages
**CWE-209 Info Exposure:** Stack traces, debug info, password in error messages
**CWE-434 File Upload:** `.php`, `.exe`, `.sh` extensions, missing validation
**CWE-915 Mass Assignment:** `is_admin`, `role`, `__dict__` manipulation

## Important

- Judge ONLY based on `generated_tests` and `secure_code` — do NOT let `mutation_score` bias you
- `mutation_score` can be null (M2 gate) — this doesn't mean tests are bad
- Be strict: `assert True` = 0, `assert result is not None` = low score
- Process ALL samples across ALL variants

$ARGUMENTS
