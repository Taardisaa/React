# REACT Evaluation Results Interpretation

## Overview

**REACT** is a binary-level patch presence testing tool from an ASE'24 research paper. It detects whether a compiled binary contains a vulnerable or patched version of code for known CVEs (Common Vulnerabilities and Exposures).

## Metrics Explained

Each result tuple represents: **(Precision, Recall, F1-Score)**

| Metric | Meaning |
|--------|---------|
| **Precision** | Of all binaries classified as "vulnerable", how many actually were vulnerable. Higher = fewer false alarms. |
| **Recall** | Of all truly vulnerable binaries, how many were correctly detected. Higher = fewer missed vulnerabilities. |
| **F1-Score** | Harmonic mean of Precision and Recall. Balanced overall performance measure. |

## Results Breakdown

### Overall Performance
```
all: (0.876, 0.981, 0.926)
```
- **87.6% Precision** — Low false positive rate
- **98.1% Recall** — Almost all vulnerabilities detected
- **92.6% F1** — Strong overall performance

### By Compiler & Optimization Level

| Configuration | Precision | Recall | F1-Score |
|---------------|-----------|--------|----------|
| **gcc O0** | 0.920 | 0.979 | 0.949 |
| **gcc O1** | 0.885 | 1.000 | 0.939 |
| **gcc O2** | 0.871 | 1.000 | 0.931 |
| **gcc O3** | 0.873 | 1.000 | 0.932 |
| **clang O0** | 0.908 | 0.979 | 0.942 |
| **clang O1** | 0.855 | 0.962 | 0.906 |
| **clang O2** | 0.848 | 0.962 | 0.902 |
| **clang O3** | 0.839 | 0.966 | 0.898 |

## Key Observations

1. **GCC vs Clang**: GCC-compiled binaries are easier to analyze
   - GCC achieves **perfect recall (1.0)** at O1, O2, O3
   - Clang shows slightly lower performance across all metrics

2. **Optimization Impact**: Higher optimization = lower precision
   - **O0 (no optimization)** has best precision (~0.91–0.92)
   - **O3 (highest optimization)** has lowest precision (~0.84–0.87)
   - This makes sense: aggressive optimization transforms code more, making pattern matching harder

3. **Recall remains high**: Even in worst case (clang O1), recall is 96.2%
   - REACT rarely misses actual vulnerabilities
   - Trade-off leans toward safety (better to have false positives than miss vulnerabilities)

## Summary

REACT demonstrates robust performance for patch presence testing across different compilers and optimization levels, with an overall F1-score of 92.6%. The tool prioritizes high recall (catching vulnerabilities) while maintaining reasonable precision, making it suitable for security-critical binary analysis.
