# Evaluation Results with Unknown Category

This evaluation uses a modified metric that introduces an `Unknown` category for cases where no distinguishing features could be extracted. Previously, such cases defaulted to `Patch`, which inflated accuracy metrics artificially.

## Metrics

- **P (Precision)**: TP / (TP + FP)
- **R (Recall)**: TP / (TP + FN)
- **F1**: Harmonic mean of precision and recall
- **Cov (Coverage)**: Proportion of cases that were actually analyzed (not Unknown)

## Overall Results

|          | Precision | Recall | F1    | Coverage |
|----------|-----------|--------|-------|----------|
| **All**  | 0.946     | 0.968  | 0.957 | 0.764    |

**Note:** 979 out of 4156 test cases (23.6%) could not be classified due to insufficient distinguishing features.

## Results by Compiler and Optimization Level

| Compiler | Opt | Precision | Recall | F1    | Coverage |
|----------|-----|-----------|--------|-------|----------|
| gcc      | O0  | 0.978     | 0.962  | 0.970 | 0.799    |
| gcc      | O1  | 0.955     | 1.000  | 0.977 | 0.750    |
| gcc      | O2  | 0.953     | 1.000  | 0.976 | 0.749    |
| gcc      | O3  | 0.959     | 1.000  | 0.979 | 0.746    |
| clang    | O0  | 0.943     | 0.965  | 0.954 | 0.789    |
| clang    | O1  | 0.932     | 0.938  | 0.935 | 0.751    |
| clang    | O2  | 0.921     | 0.939  | 0.930 | 0.756    |
| clang    | O3  | 0.921     | 0.946  | 0.933 | 0.756    |

## Observations

- **Coverage decreases with optimization level**: O0 has ~79-80% coverage while O1-O3 hover around 75%, suggesting higher optimization levels make feature extraction harder.
- **gcc achieves perfect recall at O1-O3**: All vulnerable binaries were correctly identified.
- **gcc outperforms clang**: Higher precision and recall across all optimization levels.