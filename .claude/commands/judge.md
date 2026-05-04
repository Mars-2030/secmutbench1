You are acting as an LLM-as-Judge for SecMutBench evaluation results. Your task is to judge the security relevance and test quality of LLM-generated security tests.

## Input

The user will provide a path to a results JSON file (e.g., `results/qwen3-coder_30b/baseline_results_20260312.json`). If no path is given, find the most recent `baseline_results_*.json` file under `results/`.

## Steps

1. **Load the results file** using the Read tool. Parse the JSON structure:
   - `results[]` is an array of variant results (e.g., full, no-hint, cwe-only)
   - **You MUST loop over ALL entries in `results[]`**, not just the first one
   - Each entry has `detailed_results[]` containing per-sample data

2. **For each variant** in `results[]`, and **for each sample** in that variant's `detailed_results` that has non-empty `generated_tests`:

   Read these fields:
   - `sample_id`, `cwe`, `cwe_name`
   - `secure_code` — the code being tested
   - `generated_tests` — the LLM-generated security tests to judge
   - `metrics.mutation_score` — how well tests killed mutants (can be `null` if M2 gate failed)
   - `metrics.effective_mutation_score` — MS corrected for secure-pass rate (preferred over raw MS)
   - `metrics.secure_passes` — whether tests pass on secure code
   - `difficulty`
   - `source_type` — origin of sample: SecMutBench, CWEval, SecurityEval, or LLM_Variation

   **Note on null mutation_score**: When `secure_passes` is false, `mutation_score` is null because tests that fail on secure code are not run against mutants (M2 gate). This does NOT mean the tests are bad — they may have good security logic but a syntax/import issue.

3. **Judge Security Relevance** (score 0-100):
   - Does the test target the specific CWE vulnerability?
   - Does it use realistic attack vectors (not just benign inputs)?
   - Does it verify security properties (not just functionality)?
   - Would it detect if the code were actually vulnerable?
   - Does it correctly use the mock environment (db, subprocess, hashlib, etc.)?

4. **Judge Test Quality** (score 0-100):
   - Are assertions specific and meaningful?
   - Are edge cases and boundary conditions tested?
   - Does the test follow pytest best practices?
   - Is the test maintainable and readable?
   - Does it avoid anti-patterns (bare asserts, testing implementation details)?

5. **Output results** per variant as a markdown table with columns:
   `| Sample ID | CWE | MS | Sec Relevance | Quality | Reasoning |`

6. **Save results** by writing a JSON file at `{original_path_stem}_judged_claude.json` containing the original data with ALL variants updated. Add a `judge` field per sample:
   ```json
   {
     "judge": {
       "model": "claude",
       "security_relevance": {"score": 0.85, "reasoning": "..."},
       "test_quality": {"score": 0.70, "reasoning": "..."},
       "composite": 0.79
     }
   }
   ```
   Also add per-variant summary fields: `avg_security_relevance`, `avg_test_quality`, `avg_composite_score`.

7. **Print cross-variant comparison table** after all variants are judged:
   ```
   | Variant   | Sec Rel | Quality | Composite | Avg MS |
   |-----------|---------|---------|-----------|--------|
   | full      |  73.8%  |  61.4%  |   68.7%   | 74.0%  |
   | no-hint   |  43.2%  |  69.6%  |   53.5%   | 82.8%  |
   | cwe-only  |  58.9%  |  65.6%  |   61.4%   | 87.5%  |
   ```
   For Avg MS, only average over samples where `mutation_score` is not null.

## Scoring Guidelines

- **90-100**: Excellent — tests directly target the CWE with realistic payloads and proper assertions
- **70-89**: Good — tests are security-relevant but miss some attack vectors or have weak assertions
- **50-69**: Fair — tests show some security awareness but are mostly functional
- **30-49**: Poor — tests barely touch security, mostly check functionality
- **0-29**: Irrelevant — tests have no security value for the target CWE

## Important

- Judge ONLY based on what you see in `generated_tests` and `secure_code`
- The mutation score from the pipeline is provided for context but do NOT let it bias your judgment
- Be strict but fair — real security tests need specific attack patterns, not just "assert result is not None"
- Process ALL samples across ALL variants — don't skip any with generated tests
- When computing average MS for display, skip null values (M2-gated samples) to avoid deflating scores

$ARGUMENTS
