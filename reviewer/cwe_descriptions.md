# CWE Descriptions — SecMutBench v2.8.0

This document describes all 30 CWEs covered in the SecMutBench dataset.
For each CWE: official description, impact, and expected secure coding pattern.

## CWE-117: Log Injection

**Samples in dataset**: 12

**Description**: The product writes user input to log files without neutralizing newlines or special characters.

**Impact**: Attackers can forge log entries, inject false records, or exploit log analysis tools.

**Secure coding pattern**: Strip or encode newlines and control characters from all logged user input.

---

## CWE-20: Improper Input Validation

**Samples in dataset**: 9

**Description**: The product receives input but does not validate or incorrectly validates that the input has the properties required to process it safely.

**Impact**: Attackers can craft inputs that cause unexpected behavior, bypass security controls, or trigger vulnerabilities in downstream processing.

**Secure coding pattern**: Validate type, length, range, and format of all inputs before use. Use allowlists over denylists.

---

## CWE-209: Error Message Information Exposure

**Samples in dataset**: 7

**Description**: The product generates error messages that include sensitive information about its environment, users, or data.

**Impact**: Attackers can learn internal paths, stack traces, database schemas, or other details useful for further attacks.

**Secure coding pattern**: Return generic error messages to users. Log detailed errors server-side only.

---

## CWE-22: Path Traversal

**Samples in dataset**: 15

**Description**: The product uses external input to construct a pathname for a file but does not neutralize sequences like '../' that could resolve outside the intended directory.

**Impact**: Attackers can read, modify, or delete arbitrary files on the system by manipulating file paths.

**Secure coding pattern**: Use os.path.realpath() and verify the resolved path starts with the intended base directory.

---

## CWE-295: Improper Certificate Validation

**Samples in dataset**: 14

**Description**: The product does not validate or incorrectly validates SSL/TLS certificates when making HTTPS connections.

**Impact**: Attackers can perform man-in-the-middle attacks, intercepting or modifying encrypted traffic.

**Secure coding pattern**: Always use verify=True (default) in requests. Never disable certificate verification in production.

---

## CWE-306: Missing Authentication for Critical Function

**Samples in dataset**: 16

**Description**: The product does not perform authentication for functionality that requires an established user identity.

**Impact**: Attackers can access critical functions (admin panels, data modification) without logging in.

**Secure coding pattern**: Require authentication checks before executing any privileged operation.

---

## CWE-319: Cleartext Transmission of Sensitive Information

**Samples in dataset**: 18

**Description**: The product transmits sensitive data in cleartext over a channel that can be intercepted.

**Impact**: Attackers on the network can read passwords, tokens, personal data, or other sensitive information.

**Secure coding pattern**: Encrypt sensitive data before transmission. Use TLS/HTTPS for all sensitive communications.

---

## CWE-326: Inadequate Encryption Strength

**Samples in dataset**: 10

**Description**: The product uses a cryptographic algorithm or key length that is insufficient for the required security level.

**Impact**: Attackers can break the encryption through brute force or known algorithmic weaknesses.

**Secure coding pattern**: Use recommended key sizes (RSA >= 2048, AES >= 128, EC >= 256). Follow current NIST guidelines.

---

## CWE-327: Use of Broken or Risky Cryptographic Algorithm

**Samples in dataset**: 12

**Description**: The product uses a broken or risky cryptographic algorithm (MD5, SHA-1, DES) for security-sensitive operations.

**Impact**: Attackers can exploit known weaknesses to forge signatures, find collisions, or decrypt data.

**Secure coding pattern**: Use SHA-256+ for hashing, AES-256 for encryption, bcrypt/scrypt/argon2 for passwords.

---

## CWE-328: Use of Weak Hash Function

**Samples in dataset**: 11

**Description**: The product uses a weak hash function (MD5, SHA-1) where collision resistance is required.

**Impact**: Attackers can find hash collisions, undermining data integrity verification or authentication.

**Secure coding pattern**: Use SHA-256 or SHA-3 for integrity checks. Use bcrypt/argon2 for password hashing.

---

## CWE-338: Use of Cryptographically Weak PRNG

**Samples in dataset**: 11

**Description**: The product uses a pseudo-random number generator (e.g., random module) for security-sensitive operations.

**Impact**: Attackers can predict generated tokens, session IDs, or cryptographic keys.

**Secure coding pattern**: Use secrets module or os.urandom() for security-sensitive random values.

---

## CWE-352: Cross-Site Request Forgery (CSRF)

**Samples in dataset**: 14

**Description**: The web application does not verify that a request was intentionally made by the authenticated user.

**Impact**: Attackers can trick users into performing unintended actions (transfers, password changes) on authenticated sessions.

**Secure coding pattern**: Validate a unique, unpredictable CSRF token on every state-changing request.

---

## CWE-400: Uncontrolled Resource Consumption

**Samples in dataset**: 15

**Description**: The product does not properly control allocation of resources (CPU, memory) allowing denial of service.

**Impact**: Attackers can exhaust server resources with crafted inputs (regex bombs, large payloads, recursive structures).

**Secure coding pattern**: Set timeouts, size limits, and complexity bounds. Use re.compile() with safe patterns.

---

## CWE-434: Unrestricted Upload of File with Dangerous Type

**Samples in dataset**: 5

**Description**: The product allows file upload without restricting file types, sizes, or content.

**Impact**: Attackers can upload executable files (web shells, malware) or oversized files for DoS.

**Secure coding pattern**: Validate file extension, MIME type, and size. Store uploads outside the web root.

---

## CWE-502: Deserialization of Untrusted Data

**Samples in dataset**: 10

**Description**: The product deserializes data from untrusted sources using unsafe methods (pickle, yaml.load).

**Impact**: Attackers can achieve remote code execution by crafting malicious serialized objects.

**Secure coding pattern**: Use json.loads() for untrusted data. If pickle needed, use hmac-signed payloads.

---

## CWE-601: URL Redirection to Untrusted Site (Open Redirect)

**Samples in dataset**: 11

**Description**: The product redirects users to a URL determined by user input without validating the destination.

**Impact**: Attackers can redirect users to phishing sites or malware distribution points.

**Secure coding pattern**: Validate redirect URLs against an allowlist of trusted domains.

---

## CWE-611: Improper Restriction of XML External Entity Reference (XXE)

**Samples in dataset**: 13

**Description**: The product processes XML input without disabling external entity resolution.

**Impact**: Attackers can read local files, perform SSRF, or cause denial of service via entity expansion.

**Secure coding pattern**: Use defusedxml library or disable external entity processing in XML parsers.

---

## CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)

**Samples in dataset**: 5

**Description**: The product uses user-supplied identifiers to access resources without verifying the user's authorization.

**Impact**: Attackers can access other users' data by manipulating resource IDs in requests.

**Secure coding pattern**: Always verify the authenticated user has permission to access the requested resource.

---

## CWE-643: Improper Neutralization of Data within XPath Expressions

**Samples in dataset**: 8

**Description**: The product constructs XPath queries using user input without proper sanitization.

**Impact**: Attackers can modify XPath query logic to access unauthorized XML data.

**Secure coding pattern**: Use parameterized XPath queries or sanitize all special XPath characters from input.

---

## CWE-732: Incorrect Permission Assignment for Critical Resource

**Samples in dataset**: 12

**Description**: The product creates files or resources with permissions that allow unintended access.

**Impact**: Sensitive files (keys, credentials, configs) become readable or writable by unauthorized users.

**Secure coding pattern**: Use restrictive permissions (0o600 for secrets). Use os.open() with explicit mode.

---

## CWE-74: Improper Neutralization (Injection)

**Samples in dataset**: 11

**Description**: The product constructs output using input without proper neutralization of special elements, allowing injected content to alter the intended meaning.

**Impact**: Attackers can inject commands, queries, or markup that execute with the application's privileges.

**Secure coding pattern**: Escape or sanitize all special characters before including user input in structured outputs.

---

## CWE-79: Cross-Site Scripting (XSS)

**Samples in dataset**: 13

**Description**: The product includes user-controlled input in web output without proper escaping, allowing injection of client-side scripts.

**Impact**: Attackers can execute scripts in victims' browsers to steal sessions, deface pages, or redirect users.

**Secure coding pattern**: Apply context-appropriate output encoding (html.escape for HTML context, JSON encoding for JS context).

---

## CWE-798: Use of Hardcoded Credentials

**Samples in dataset**: 13

**Description**: The product contains hardcoded passwords, API keys, or cryptographic keys in source code.

**Impact**: Attackers who gain access to code (via repository, decompilation) obtain valid credentials.

**Secure coding pattern**: Load credentials from environment variables, vaults, or configuration files excluded from VCS.

---

## CWE-862: Missing Authorization

**Samples in dataset**: 10

**Description**: The product does not perform authorization checks when accessing a resource or performing an action.

**Impact**: Attackers can perform actions or access data beyond their intended permission level.

**Secure coding pattern**: Check user roles/permissions before every privileged operation. Use RBAC or ABAC.

---

## CWE-863: Incorrect Authorization

**Samples in dataset**: 5

**Description**: The product performs authorization checks but implements them incorrectly.

**Impact**: Attackers can bypass authorization through logic flaws in permission checking.

**Secure coding pattern**: Use well-tested authorization frameworks. Apply principle of least privilege.

---

## CWE-89: SQL Injection

**Samples in dataset**: 16

**Description**: The product constructs SQL queries using string concatenation with user input instead of parameterized queries.

**Impact**: Attackers can read, modify, or delete database contents, bypass authentication, or execute system commands.

**Secure coding pattern**: Use parameterized queries (cursor.execute(sql, params)) instead of string formatting.

---

## CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

**Samples in dataset**: 5

**Description**: The product receives input that specifies object attributes to modify without restricting which attributes can be changed.

**Impact**: Attackers can modify sensitive attributes (is_admin, role) through mass assignment.

**Secure coding pattern**: Use an allowlist of modifiable attributes. Never pass raw user input to setattr().

---

## CWE-918: Server-Side Request Forgery (SSRF)

**Samples in dataset**: 15

**Description**: The product makes HTTP requests to URLs controlled by user input without validating the destination.

**Impact**: Attackers can access internal services, cloud metadata endpoints, or private network resources.

**Secure coding pattern**: Validate URLs against allowlisted hosts/schemes. Block private/internal IP ranges.

---

## CWE-94: Code Injection

**Samples in dataset**: 15

**Description**: The product allows user input to be executed as code without adequate restriction of the code constructs that are allowed.

**Impact**: Attackers can execute arbitrary code with the application's privileges.

**Secure coding pattern**: Use AST-based validation to restrict allowed constructs. Avoid eval()/exec() on user input.

---

## CWE-95: Eval Injection

**Samples in dataset**: 8

**Description**: The product uses eval() or similar functions with user-provided input, allowing execution of arbitrary expressions.

**Impact**: Attackers can execute arbitrary Python expressions, access the file system, or import dangerous modules.

**Secure coding pattern**: Parse expressions with ast.literal_eval() or a restricted AST walker instead of eval().

---
