# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

REACT is a research tool for IR-level patch presence testing in binaries (ASE'24 paper replication package). It analyzes LLVM bitcode to detect whether compiled binaries contain vulnerability patches by comparing semantic effects extracted via symbolic execution.

## Build and Run

```bash
# Build and run the full test suite
cargo run --release

# Build only
cargo build --release
```

**Environment requirement:** LLVM 14 must be installed. If `llvm-sys` fails to find it, set `LLVM_SYS_140_PREFIX` to your LLVM 14 installation path.

**Output:** Results printed to stdout; detailed per-CVE-bitcode pair results written to `log.txt`.

## Architecture

### Workspace Structure

The project is a Cargo workspace with three crates:

- **react/** - Main entry point and test harness. Loads CVE metadata and test cases, orchestrates analysis, computes metrics.
- **ir-analysis/** - Core analysis engine. Performs symbolic execution on LLVM IR, extracts semantic effects, and classifies targets.
- **source-analysis/** - Parses unified diff files to identify changed functions and guide IR analysis.

### Analysis Pipeline

1. **Signature Generation (IRAnalysis):** Compares vulnerable vs patched LLVM bitcode, extracts semantic "effects" via symbolic execution, generates ranked differentiating features.

2. **Target Classification (IRAnalysis2):** Tests target bitcode against the signature. Falls back to O3-optimized variants if standard analysis fails.

### Key Modules in ir-analysis

- `emulator.rs` - Symbolic execution engine that walks CFG and extracts effects
- `effect.rs` - Effect types (Call, Return, ParameterWrite, GlobalWrite, Condition) and matching logic
- `expr.rs` - Expression AST for symbolic state representation
- `smt.rs` - SMT solver integration for constraint-based reasoning
- `maxweight.rs` - Max-weight bipartite matching for effect comparison
- `module/` - LLVM IR wrapper abstractions (KModule, KFunction, KBlock, KInstruction)
- `analysis/` - CFG construction and caching

### Feature Flags (ir-analysis)

Used for research experimentation:
- `wsmt` - Skip SMT solving
- `wrefine` - Skip effect refinement
- `wrank` - Use simpler size-based ranking only

## Dataset Structure

Dataset must be placed in `./dataset/`:

```
dataset/
├── CVE_info.jsonl          # CVE metadata
├── test.jsonl              # Test cases with ground truth
├── diff/                   # Source code diffs
│   └── {CVE-ID}_{commit}.diff
└── bitcodes/               # LLVM bitcode files
    └── {project}/
        ├── {CVE-ID}_vuln.bc
        ├── {CVE-ID}_patch.bc
        └── {target}.bc
```

Download dataset from: https://figshare.com/s/77da6a3ec24d20540dad

## CLI Options

The main binary supports filtering via command-line arguments:
- `--cve` - Filter by specific CVE
- `--test` - Filter test cases
- `--binary` - Filter by binary name
- `--exclude` - Exclude patterns
