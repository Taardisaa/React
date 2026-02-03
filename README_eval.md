# Evaluation Dataset Usage (REACT)

This document explains how the **checker** (the `react` binary) consumes the dataset during evaluation. All statements below are derived from the code under `react/` and `ir-analysis/`.

## Entry point

- **Executable**: `react/src/main.rs`
- **Dataset root**: `react/src/config.rs` sets `DATASET_DIR = <cwd>/dataset` and defines the fixed paths for all dataset artifacts.

## Dataset files and how they are used

### 1) `dataset/CVE_info.jsonl`

**Where read:** `react/src/dataset.rs::read_cves` via `main.rs`.

**Fields used:**
- `CVE` → `Cve.id`
- `commit` → `Cve.commit`
- `project` → `Cve.project`
- Other fields (`func`, `vuln`, `patch`, `file`) are loaded but **not** referenced in evaluation logic in `main.rs`.

**How it is used in evaluation:**
- The evaluator loads all CVE metadata into a `HashMap<String, Cve>` keyed by CVE id.
- For each CVE that appears in `test.jsonl`, the evaluator retrieves the corresponding `Cve` entry to:
  - **Build the diff path**: `dataset/diff/{CVE-ID}_{commit-prefix}.diff`, where `commit-prefix` is `cve.commit[0..6]`.
  - **Build the reference bitcode paths**: `dataset/bitcodes/{project}/{CVE-ID}_vuln.bc` and `dataset/bitcodes/{project}/{CVE-ID}_patch.bc`.

### 2) `dataset/test.jsonl`

**Where read:** `react/src/dataset.rs::read_tests` via `main.rs`.

**Fields used per test case:**
- `file` → target bitcode name (without `.bc`)
- `cve` → CVE group key
- `ground_truth` → expected label (`vuln` or `patch`)
- `project` → which project subfolder in `bitcodes/`
- `commit` is loaded but **not** used in evaluation logic.

**How it is used in evaluation:**
- All rows are grouped **by CVE id** (`read_tests` groups into `Vec<(CVE, Vec<TestCase>)>`).
- For each test case, the evaluator builds the **target bitcode path**:
  - `dataset/bitcodes/{project}/{file}.bc`
- The `ground_truth` value is used to compute **TP/TN/FP/FN** and precision/recall/F1.

### 3) `dataset/diff/{CVE-ID}_{commit-prefix}.diff`

**Where read:** `ir-analysis/src/lib.rs` through `source_analysis::SourceDiff::from_path`.

**How it is used in evaluation:**
- For each CVE, the evaluator constructs `IRAnalysis2` with:
  - `vuln` reference bitcode
  - `patch` reference bitcode
  - the **source diff path**
- The diff is parsed at source level to:
  - Inspect only `.c` files
  - Extract function names from hunk headers
  - Collect added and deleted line numbers for each function
- These function names and line lists guide the **signature/effect generation** used to distinguish patch vs vuln in IR analysis.

### 4) `dataset/bitcodes/{project}/...`

**Reference bitcodes (per CVE):**
- `dataset/bitcodes/{project}/{CVE-ID}_vuln.bc`
- `dataset/bitcodes/{project}/{CVE-ID}_patch.bc`

**Target bitcodes (per test case):**
- `dataset/bitcodes/{project}/{file}.bc` where `{file}` comes from `test.jsonl`.

**How they are used in evaluation:**
- The checker creates `IRAnalysis2` with the **reference pair** (vuln + patch) and the diff.
- Each **target** bitcode is then classified by `IRAnalysis2::test` as `IRState::Vuln` or `IRState::Patch`.
- The classification is compared with the test case `ground_truth`.

**Fallback behavior:**
- If the initial IR analysis fails (returns an internal error), `IRAnalysis2` tries an **optimized** fallback pair by replacing `.bc` with `_O3.bc` for both reference files.
- If those optimized reference bitcodes are missing, the checker **defaults to `Vuln`** for that test case.

### 5) `dataset/binary/` (not used in evaluation)

`BINARIES_DIR` is defined but **not used** by the evaluator. It is only referenced by `react/src/bin/extract_target_bitcode.rs`, which is a **dataset preparation** tool (not part of runtime evaluation).

## End-to-end evaluation flow

1) Load **CVE metadata** from `CVE_info.jsonl`.
2) Load and **group test cases by CVE** from `test.jsonl`.
3) For each CVE group:
   - Build the **diff path** using the CVE id and the **first 6 chars** of `commit` from `CVE_info.jsonl`.
   - Build the **reference bitcode paths** `{CVE}_vuln.bc` and `{CVE}_patch.bc` under the project directory.
   - Create `IRAnalysis2` with the reference pair and the diff.
4) For each test case in that CVE group:
   - Build the **target bitcode path** from `project` and `file`.
   - Run the analysis to label it `vuln` or `patch`.
   - Compare with `ground_truth`.
5) Report precision/recall/F1:
   - **Per CVE** (printed and appended to `log.txt`)
   - **Overall** across all CVEs
   - **Per compiler/opt level** derived from the `file` naming scheme

## Filtering and partial runs

The evaluator can restrict which dataset entries are used:

- `--cve <pattern>`: only CVEs whose id **contains** the pattern.
- `--exclude <pattern>`: skip CVEs whose id **contains** the pattern.
- `--test <N>`: only the first `N` test cases in each CVE group.
- `--binary <pattern>`: only test cases whose `file` **contains** the pattern.

These filters apply **before** scoring, so only the selected subset contributes to metrics.

## Naming conventions the evaluator assumes

From `README.md` and `react/src/dataset.rs` usage:

- **Target test case file names** encode compiler and optimization:
  - `filename_version_optimization_compiler`
  - Example: `libxml2_v2.10.0_O3_x86_gcc`
- **Reference bitcodes** for CVEs are named:
  - `{CVE-ID}_vuln.bc` and `{CVE-ID}_patch.bc`
- **Diff files** are named:
  - `{CVE-ID}_{commit-prefix}.diff` where `commit-prefix` is the first 6 chars of `CVE_info.jsonl` `commit`.

## Output artifacts

- `log.txt` is rewritten at the start of each run and then appended with:
  - each test case result (`<testcase> tested: <result>`)
  - per-CVE precision/recall/F1
  - overall precision/recall/F1

---

If you want, I can extend this document with a dataset preparation section (how `extract_target_bitcode.rs` and `build_reference_bitcode.rs` use the same JSONL files to generate bitcodes).
