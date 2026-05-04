# Results Summary Notebook Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a Jupyter notebook that (1) analyzes the dataset2.json benchmark composition (CWEs, operators, mutants, sources, difficulties) and (2) loads all LLM evaluation results and judge scores to generate publication-quality charts.

**Architecture:** Single `.ipynb` notebook with two parts. Part 1: Dataset analysis — loads `data/dataset2.json` and charts CWE distribution, operator frequencies, mutant categories, source types, difficulty splits. Part 2: Model evaluation — loads result JSONs from `results/`, charts mutation scores, kill breakdowns, judge scores, heatmaps, correlations.

**Tech Stack:** Python 3.11, pandas, matplotlib, seaborn, numpy, json (all already installed in `sectest` env)

---

## Data Inventory

| Model | Samples | Baseline | Security Judge | Quality Judge | OpenAI Judge |
|-------|---------|----------|----------------|---------------|--------------|
| qwen3-coder:30b | 339 | ✅ | ✅ | ✅ | ✅ |
| deepseek-coder-v2 | 339 | ✅ | ✅ | ✅ | ✅ |
| qwen2.5-coder:14b | 339 | ✅ | ✅ | ✅ | ✅ |
| gpt-5.2-2025-12-11 | 339 | ✅ | ✅ | ✅ | ✅ |
| gpt-oss-120b | 339 | ✅ | ✅ | ✅ | ✅ |
| gpt-5-mini (339) | 339 | ✅ | ✅ | ✅ | — |
| glm-5:cloud | 339 | ✅ | — | — | ✅ |
| kimi-k2.5:cloud | 339 | ✅ | — | — | ✅ |
| reference_tests | 339 | ✅ (special) | — | — | — |
| static_analysis | 339 | ✅ (special) | — | — | — |

**Key schema fields per sample:**
- `metrics.mutation_score`, `metrics.mutants_killed`, `metrics.mutants_total`, `metrics.valid_tests`, `metrics.secure_passes`, `metrics.tests_count`
- `difficulty` (easy/medium/hard), `cwe`, `source_type`
- `judge_security.score`, `judge_security.cwe_addressed`, `judge_security.attack_vectors_tested`
- `judge_quality.score`, `judge_quality.assertions_count`, `judge_quality.edge_cases_covered`, `judge_quality.issues_found`
- `judge.security_relevance.score`, `judge.test_quality.score`, `judge.composite` (OpenAI judge)

**Top-level aggregate fields per model result:**
- `avg_mutation_score`, `avg_security_mutation_score`, `avg_incidental_score`, `avg_crash_score`
- `avg_security_precision`, `secure_pass_rate`

---

## Dataset2.json Schema

- **339 samples**, **30 CWEs**, **1869 mutants** (avg 5.51/sample)
- `source_type`: original (81) / variation (258)
- `difficulty`: easy (136) / medium (101) / hard (102)
- **25 unique operators** — top: RVALID (151), WEAKCRYPTO (128), INPUTVAL (119), DESERIAL (106), RMAUTH (105)
- `mutant.mutant_category`: cwe_specific (1252, 67%) / generic (617, 33%)
- `mutant.variant_type`: removal (1639) / pass_variant (211) / combination (19)
- Each sample has: `cwe`, `cwe_name`, `difficulty`, `source_type`, `mutation_operators[]`, `mutants[]`
- Each mutant has: `operator`, `mutant_category`, `variant_type`, `description`

## File Structure

- **Create:** `results_summary.ipynb` — the main notebook (root of SecMutBench)

No other files needed. The notebook is self-contained.

---

## Chunk 1: Dataset Analysis (Part 1)

### Task 1: Create notebook with dataset loading cell

**Files:**
- Create: `results_summary.ipynb`

- [ ] **Step 1: Write dataset loading cell**

Cell 1 (markdown): Title "# SecMutBench Results Summary" + version info
Cell 2 (code): Imports (json, pandas, numpy, matplotlib, seaborn). Set global rcParams (dpi=150, font.size=12). Define MODEL_COLORS dict for consistent colors. Load `data/dataset2.json`. Build `dataset_df` (one row per sample): `id`, `cwe`, `cwe_name`, `difficulty`, `source_type`, `num_mutants`, `operators` (list). Build `mutants_df` (one row per mutant): `sample_id`, `cwe`, `operator`, `mutant_category`, `variant_type`.

- [ ] **Step 2: Run to verify**

Expected: `dataset_df` has 339 rows, `mutants_df` has 1869 rows.

---

### Task 2: CWE distribution chart

- [ ] **Step 1: Write chart cell**

Cell 3 (markdown): "## Dataset Composition"
Cell 4 (markdown): "### CWE Distribution"
Cell 5 (code): Horizontal bar chart — y-axis = CWE IDs (e.g., "CWE-89 SQL Injection"), x = sample count. Sort by count descending. Color by difficulty composition (stacked: easy/medium/hard). `figsize=(12, 10)`.

---

### Task 3: Mutation operator frequency chart

- [ ] **Step 1: Write chart cell**

Cell 6 (markdown): "### Mutation Operator Frequency"
Cell 7 (code): Horizontal bar chart — y = operator name, x = number of mutants using that operator. Sort descending. Color-code by `mutant_category` (cwe_specific vs generic) using stacked bars. `figsize=(12, 8)`.

---

### Task 4: Mutant category and variant type charts

- [ ] **Step 1: Write chart cell**

Cell 8 (markdown): "### Mutant Categories & Variant Types"
Cell 9 (code): Two subplots side by side (`figsize=(12, 5)`).
Left: Pie chart of `mutant_category` (cwe_specific vs generic) with counts and percentages.
Right: Pie chart of `variant_type` (removal, pass_variant, combination) with counts and percentages.

---

### Task 5: Source type and difficulty distribution

- [ ] **Step 1: Write chart cell**

Cell 10 (markdown): "### Source Type & Difficulty Distribution"
Cell 11 (code): Two subplots side by side (`figsize=(12, 5)`).
Left: Bar chart of `source_type` (original vs variation) with sample counts.
Right: Bar chart of `difficulty` (easy/medium/hard) with sample counts, colored green/orange/red.

---

### Task 6: Mutants per sample distribution

- [ ] **Step 1: Write chart cell**

Cell 12 (markdown): "### Mutants per Sample"
Cell 13 (code): Histogram of `num_mutants` per sample with bins for each integer value (4-9). Annotate mean, min, max. `figsize=(10, 5)`.

---

### Task 7: CWE × Operator heatmap

- [ ] **Step 1: Write chart cell**

Cell 14 (markdown): "### CWE × Operator Coverage"
Cell 15 (code): From `mutants_df`, pivot_table: rows=CWE, columns=operator, values=count. Plot heatmap showing which operators apply to which CWEs. `figsize=(18, 12)`, `cmap='Blues'`, annotate non-zero cells.

---

### Task 8: Operators per CWE bar chart

- [ ] **Step 1: Write chart cell**

Cell 16 (markdown): "### Operators per CWE"
Cell 17 (code): For each CWE, count unique operators used. Bar chart sorted descending. Shows CWE coverage breadth. `figsize=(12, 6)`.

---

## Chunk 2: Model Evaluation Results (Part 2)

### Task 9: Load model evaluation results

- [ ] **Step 1: Write model results loading cell**

Cell 18 (markdown): "# Part 2: Model Evaluation Results"
Cell 19 (code): Load all baseline JSON files from `results/*/baseline_results_*.json` (skip `_judged`, `_openai`, `archive/`). For gpt-5-mini use the 339-sample run (`baseline_results_20260314_230056.json`). Build `models_df` with: `model`, `samples`, `avg_mutation_score`, `avg_security_mutation_score`, `avg_incidental_score`, `avg_crash_score`, `avg_security_precision`, `secure_pass_rate`. Build `samples_df` (one row per model×sample): `model`, `sample_id`, `cwe`, `difficulty`, `source_type`, `mutation_score`, `mutants_killed`, `mutants_total`, `valid_tests`, `secure_passes`, `tests_count`. Short display names: `qwen3-30b`, `qwen2.5-14b`, `deepseek-v2`, `gpt-5-mini`, `gpt-5.2`, `gpt-oss-120b`, `glm-5`, `kimi-k2.5`.

- [ ] **Step 2: Run to verify**

Expected: `models_df` has 8 rows, `samples_df` has ~2712 rows (8×339).

---

### Task 10: Load judge scores

- [ ] **Step 1: Write judge loading cell**

Cell 20 (code): For each model with `_judged_security.json`, extract per-sample `judge_security.score`. Same for `_judged_quality.json` → `judge_quality.score`. Same for `_openai_judged.json` → `judge.security_relevance.score`, `judge.test_quality.score`, `judge.composite`. Merge into `samples_df` as: `sec_judge_score`, `qual_judge_score`, `openai_sec_score`, `openai_qual_score`, `openai_composite`. Missing = NaN.

---

### Task 11: Load reference test and static analysis baselines

- [ ] **Step 1: Write reference/static loading cell**

Cell 21 (code): Load `reference_tests_v28.json` summary → add row to `models_df` with model="Reference". Load `static_analysis_baseline_20260313_155936.json` → extract summary and add row.

- [ ] **Step 2: Run to verify**

Expected: `models_df` now has 10 rows.

---

### Task 12: Overall performance bar chart

- [ ] **Step 1: Write chart cell**

Cell 22 (markdown): "## Overall Model Performance"
Cell 23 (code): Grouped bar chart — x = model names, bars: Mutation Score, Security Mutation Score, Secure-Pass Rate. Sort by mutation score descending. `figsize=(14, 6)`, annotate bars with values.

---

### Task 13: Kill type breakdown stacked bar

- [ ] **Step 1: Write chart cell**

Cell 24 (markdown): "## Kill Type Breakdown"
Cell 25 (code): Stacked bar — x = model, segments: Security kills (semantic), Incidental, Crash, Survived. Colors: green/yellow/red/gray.

---

### Task 14: Performance by difficulty heatmap

- [ ] **Step 1: Write chart cell**

Cell 26 (markdown): "## Performance by Difficulty"
Cell 27 (code): From `samples_df`, group by `(model, difficulty)`, mean `mutation_score`. Heatmap, `cmap='YlOrRd'`, `figsize=(10, 8)`.

---

### Task 15: Performance by CWE heatmap

- [ ] **Step 1: Write chart cell**

Cell 28 (markdown): "## Mutation Score by CWE"
Cell 29 (code): From `samples_df`, group by `(model, cwe)`, mean `mutation_score`. Heatmap `figsize=(18, 10)`, sorted CWEs by avg score.

---

### Task 16: Radar chart comparing top models

- [ ] **Step 1: Write chart cell**

Cell 30 (markdown): "## Multi-Dimensional Model Comparison"
Cell 31 (code): Radar chart with axes: Mutation Score, Security MS, Security Precision, Secure-Pass Rate, (1 - Crash Rate). Top 5 models. Matplotlib polar projection.

---

### Task 17: LLM-as-Judge security scores

- [ ] **Step 1: Write chart cell**

Cell 32 (markdown): "## LLM-as-Judge: Security Evaluation"
Cell 33 (code): Box plot of `sec_judge_score` per model + subplot for `openai_sec_score`. `figsize=(14, 6)`.

---

### Task 18: LLM-as-Judge quality scores

- [ ] **Step 1: Write chart cell**

Cell 34 (markdown): "## LLM-as-Judge: Test Quality Evaluation"
Cell 35 (code): Box plot of `qual_judge_score` per model + subplot for `openai_qual_score`.

---

### Task 19: Judge composite scores comparison

- [ ] **Step 1: Write chart cell**

Cell 36 (markdown): "## Judge Composite Scores"
Cell 37 (code): Bar chart of OpenAI composite scores per model with error bars (std). Sort descending.

---

### Task 20: Security judge — CWE addressed rate

- [ ] **Step 1: Write chart cell**

Cell 38 (markdown): "## CWE Addressed Rate (Security Judge)"
Cell 39 (code): % samples where `judge_security.cwe_addressed == True` per model. Bar chart.

---

### Task 21: Correlation scatter — mutation score vs judge scores

- [ ] **Step 1: Write chart cell**

Cell 40 (markdown): "## Correlation: Mutation Score vs Judge Scores"
Cell 41 (code): Scatter: `mutation_score` vs `sec_judge_score`, colored by model, regression line. Second subplot: vs `openai_composite`. Display Pearson r.

---

### Task 22: Summary statistics table

- [ ] **Step 1: Write summary cell**

Cell 42 (markdown): "## Summary Statistics"
Cell 43 (code): Display `models_df` styled with conditional formatting (green=high, red=low). Round to 3 decimals.

---

### Task 23: Source type analysis

- [ ] **Step 1: Write chart cell**

Cell 44 (markdown): "## Performance by Source Type"
Cell 45 (code): Group by `(model, source_type)`, mean mutation_score. Bar chart: original vs variation per model.

---

### Task 24: Final commit

- [ ] **Step 1: Run all cells top to bottom to verify**

```bash
jupyter nbconvert --execute results_summary.ipynb --to notebook --inplace
```

- [ ] **Step 2: Commit**

```bash
git add results_summary.ipynb
git commit -m "feat: add results summary notebook with charts and judge analysis"
```

---

## Implementation Notes

- Use `plt.tight_layout()` on every figure to prevent label clipping
- Use consistent color mapping: assign each model a fixed color via a dict so colors are consistent across all charts
- Set `plt.rcParams` globally: `font.size=12`, `figure.dpi=150`
- For models with multiple runs (gpt-5-mini has 3), use only the 339-sample full run
- Handle NaN gracefully in judge columns — use `dropna()` before plotting
- Short model names for readability: `qwen3-30b`, `qwen2.5-14b`, `deepseek-v2`, `gpt-5-mini`, `gpt-5.2`, `gpt-oss-120b`, `glm-5`, `kimi-k2.5`, `reference`, `static`
