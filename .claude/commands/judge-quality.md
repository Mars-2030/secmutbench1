You are an expert software tester evaluating the quality of LLM-generated security tests. Your task is to assess test craftsmanship, not security relevance (that's handled by `/judge-security`).

## Input

The user will provide a path to a results JSON file. If no path is given, find the most recent `baseline_results_*.json` file under `results/` (excluding `_judged` files).

## Steps

1. **Load the results file**. It has `results[]` — an array of variant results. **Loop over ALL variants.**

2. **For each sample** with non-empty `generated_tests`, evaluate test quality using the criteria and context below.

3. **For each sample, reason step by step:**
   a. How many test functions are there? Are they distinct or copy-pasted?
   b. Are assertions specific and meaningful, or generic (`assert True`, `is not None`)?
   c. Does the test use `with pytest.raises(...)` context managers correctly?
   d. Are there descriptive test names and docstrings?
   e. Does it test edge cases and boundary conditions?
   f. Does it avoid anti-patterns (try/except pass, bare assert, class definitions)?
   g. Does it correctly use the mock environment? (See Mock Reference below)
   h. Does it call the target function (`entry_point`)?

4. **Score (0-100)** and produce structured output.

5. **Save results** to `{original_stem}_judged_quality.json` with ALL variants updated. Add per sample:
   ```json
   {
     "judge_quality": {
       "model": "claude",
       "score": 0.70,
       "assertions_count": 5,
       "edge_cases_covered": 3,
       "follows_best_practices": true,
       "issues_found": ["Missing boundary test for empty input", "Duplicate test bodies for test_2 and test_3"],
       "reasoning": "Good assertion variety with 5 meaningful assertions. Uses pytest.raises correctly. However, test_2 and test_3 are near-duplicates and no empty-input edge case is tested.",
       "confidence": 0.85
     }
   }
   ```

6. **Print summary** per variant and a cross-variant comparison table.

## Scoring Guidelines

- **90-100 Excellent**: Multiple distinct tests, specific assertions with messages, edge cases, pytest best practices, readable
- **70-89 Good**: Good test structure but missing some edge cases or has minor issues
- **50-69 Fair**: Tests exist and run, but assertions are generic or tests are duplicated
- **30-49 Poor**: Minimal tests, `assert True`, `assert result is not None`, no edge cases
- **0-29 Irrelevant**: Empty, broken, or completely non-functional tests

## Quality Criteria (with point weights)

### 1. Test Count & Diversity (0-15 pts)
- 5+ distinct tests: 15
- 4 tests: 12
- 3 tests: 10
- 2 tests: 7
- 1 test: 3
- Penalty: -15 if tests are copy-pasted duplicates (>85% body similarity)

### 2. Assertion Quality (0-25 pts)
- 8+ assertions: 25
- 5-7 assertions: 20
- 3-4 assertions: 15
- 1-2 assertions: 8
- Bonus: +5 for assertion messages (`assert x, "explanation"`)
- Penalty: -10 per `assert True`
- Penalty: -5 if most assertions are `is not None`

### 3. Pytest Best Practices (0-15 pts)
- Uses `pytest.raises()`: +5
- Uses `with pytest.raises()` (context manager): +5
- Doesn't redundantly `import pytest` (already available): +3
- Penalty: -5 for non-mock class definitions

### 4. Structure & Readability (0-15 pts)
- Docstrings on most tests: +8
- Descriptive test names (>15 chars): +7
- Penalty: -5 for `try/except pass` pattern (swallows errors)

### 5. Edge Cases (0-10 pts)
- Tests boundary conditions (empty, null, negative, overflow, special chars): +10
- Some edge awareness: +5

### 6. Mock Environment Usage (0-10 pts)
- Correctly calls `reset()` before tests: +5
- Uses correct mock for the CWE: +5
- Penalty: -5 for using wrong mock (e.g., `db.` for CWE-78)

### 7. Target Function (0-10 pts)
- Calls the entry point function: +10
- Penalty: -10 if never calls target

## Mock Environment Reference

Tests run with these mocks (already available, no imports needed):
- `db` (MockDatabase): `.execute()`, `.last_query`, `.last_params`, `.reset()`
- `subprocess` (MockSubprocess): `.run()`, `.injection_detected`, `.last_shell`, `.reset()`
- `fs` (MockFileSystem): `.read_file()`, `.file_exists()`, `.base_dir`
- `hashlib` (MockCrypto): `.md5()`, `.sha256()`, `.weak_algorithm_used`, `.reset()`
- `pickle` (MockPickle): `.loads()`, `.unsafe_load_called`
- `yaml` (MockYAML): `.load()`, `.safe_load()`, `.unsafe_load_called`
- `requests` (MockHTTPClient): `.get()`, `.post()`, `.ssrf_attempted`, `.last_url`, `.reset()`
- `xml_parser` (MockXMLParser): `.parse_unsafe()`, `.external_entities_resolved`
- `env` (MockEnvironment): `.get()`, `.access_log`, `.sensitive_accessed`
- `auth` (MockAuthenticator): `.login()`, `.auth_attempts`
- `mock_eval` (MockEval): `.eval()`, `.unsafe_eval_called`, `.injection_detected`
- Standard libs: `os`, `sys`, `re`, `json`, `html`, `base64`, `ast`, `inspect`

## Important

- Judge test QUALITY, not security relevance — a well-written functional test can score high here even if it doesn't target the CWE
- `mutation_score` can be null (M2 gate) — don't penalize for this
- Be strict on anti-patterns: `assert True`, `try/except pass`, duplicate bodies
- Process ALL samples across ALL variants

$ARGUMENTS
