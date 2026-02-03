# React Patch Verification Algorithm

This document describes how the React tool classifies a target bitcode file as **patched** or **vulnerable**. It is based on the implementation in `ir-analysis/src/lib.rs`, `ir-analysis/src/emulator.rs`, `ir-analysis/src/effect.rs`, `source-analysis/src/lib.rs`, and the entrypoint wiring in `react/src/main.rs`.

## High-level idea

React builds a **signature** of the code change between a vulnerable and patched version using:

- The **source diff** (to identify modified functions).
- The **LLVM bitcode** of the vulnerable and patched builds (to extract semantic effects).

It then checks a target bitcode file to see whether it exhibits **vulnerable-only effects** or **patched-only effects** for those functions. If any decisive effect is found, it returns a classification.

## Inputs and artifacts

- **Source diff**: `dataset/diff/<CVE>_<commit>.diff` (selected via `DIFF_DIR`).
- **Vulnerable bitcode**: `BITCODE_DIR/<project>/<cve>_vuln.bc`.
- **Patched bitcode**: `BITCODE_DIR/<project>/<cve>_patch.bc`.
- **Target bitcode**: `BITCODE_DIR/<project>/<file>.bc` (per test case).

## Step-by-step algorithm

### 1) Build a function-level change map from the diff

`SourceDiff::from_path()` parses the unified diff and:

- Finds function names in each hunk header (C only).
- Records line numbers added/removed per function.
- Tracks if the change is a *pure deletion* or *pure addition*.

This yields a set of function names to analyze.

### 2) Generate effect signatures for changed functions

`IRAnalysis::generate()` builds signatures by comparing the vulnerable and patched bitcode:

For each changed function (present in both builds):

1. **Extract effects and strings** from the vulnerable and patched versions by symbolic execution:
   - `Generator::execute_function()` walks the CFG, tracks symbolic state, and emits effects and string constants.
2. **Compute set differences**:
   - `vuln_only_effects = vuln_effects \ patch_effects`
   - `patch_only_effects = patch_effects \ vuln_effects`
   - Same for strings.
3. **Refine** effects (unless the `wrefine` feature disables this):
   - Each effect is simplified to a smaller discriminating sub-effect not present on the other side.
4. **Match and rank** effects (unless `wrank` changes behavior):
   - Effects are paired via similarity matching.
   - Pairs where both sides exist are prioritized; ties are broken by effect complexity.

The result is a sorted list of `(function, vuln_effect?, patch_effect?)` pairs plus per-function string diffs.

### 3) Test the target bitcode (standard build)

`IRAnalysis::test(target)` performs classification in this order:

1. **Load target module** and find the modified functions that exist in it.
2. For each effect pair (in rank order), for each function:
   - **Extract effects/strings for the target function** (cached per function).
   - **String check (fast heuristic)**:
     - If vulnerable-only strings appear and patched-only strings do not, return **Vuln**.
     - If patched-only strings appear and vulnerable-only strings do not, return **Patch**.
   - **Effect check (fast path)**:
     - If target contains the vulnerable-only effect, return **Vuln**.
     - If target contains the patched-only effect, return **Patch**.
   - **Effect check (slow SMT path)**:
     - If direct containment fails, SMT reasoning (`smt::contains`) is used unless `wsmt` is enabled to skip it.
3. **If nothing is decisive**:
   - If the diff is a pure deletion and every patch effect is `None`, return **Patch**.
   - If the diff is a pure addition and every vuln effect is `None`, return **Vuln**.
   - Otherwise return **Err(functions_effects)** to trigger the O3 fallback.

### 4) O3 fallback (optimization-level rescue)

`IRAnalysis2::test()` first runs the standard analysis. If it returns `Err`, it:

1. Builds a new analysis using `_O3` bitcode files (`*_vuln_O3.bc`, `*_patch_O3.bc`) if they exist.
2. Reuses the **already-extracted target effects** from the standard pass.
3. Calls `IRAnalysis::test2()` which repeats the **effect check** only (no strings) against the O3 signature.

If the O3 bitcode files are missing, the tool returns **Vuln** by default.

## What counts as an “effect”

Effects are semantic observations extracted from the IR (see `ir-analysis/src/effect.rs`):

- `Call(function, args)`
- `Return(value)`
- `ParameterWrite(ptr, value)`
- `GlobalWrite(value)`
- `Condition(cond)`

### Concrete examples (conceptual)

These are illustrative examples of what each effect *means* in C/IR terms. The exact `Expr` string shapes come from the symbolic execution in `ir-analysis/src/emulator.rs`, but the intent is as follows:

- `Call(function, args)`
  - Example C: `memcpy(dst, src, len);`
  - Example effect: `Call(memcpy, [dst, src, len])`
  - Notes: Call equality is name-based (before any `.` suffix) and compares a prefix of args.

- `Return(value)`
  - Example C: `return n + 1;`
  - Example effect: `Return(Add(n, 1))`
  - Notes: A `return 0` is intentionally ignored in `State::add_effect`.

- `ParameterWrite(ptr, value)`
  - Example C: `*out = 42;` where `out` is a function parameter pointer
  - Example effect: `ParameterWrite(out, 42)`
  - Notes: Triggered when a store writes through a pointer expression that contains a parameter.

- `GlobalWrite(value)`
  - Example C: `g_counter = g_counter + 1;`
  - Example effect: `GlobalWrite(g_counter + 1)`

- `Condition(cond)`
  - Example C: `if (len > max) { ... }`
  - Example effect: `Condition(len > max)`
  - Notes: Emitted from branch/switch conditions during CFG traversal.

### String features (also collected)

String constants are extracted alongside effects and are used as a fast heuristic. Examples:

- Vulnerable side contains string `"overflow"` and patched side does not:
  - Target includes `"overflow"` => **Vuln**
- Patched side contains string `"invalid length"` and vulnerable side does not:
  - Target includes `"invalid length"` => **Patch**

The string rule is only decisive when one side’s strings appear and the other side’s do not.

Effects are compared with a custom equality and similarity scheme and can be refined by reducing the expression structure.

## Decision summary (pseudocode)

```text
build SourceDiff from diff
build signatures from vuln+patch bitcode

for target:
  for each ranked (func, vuln_eff?, patch_eff?):
    if func exists in target:
      effects, strings := execute_function(func)
      if strings indicate vuln-only: return Vuln
      if strings indicate patch-only: return Patch
      if effects contain vuln_eff: return Vuln
      if effects contain patch_eff: return Patch
      if SMT proves containment: return Vuln/Patch

  if pure deletion and no patch effects: return Patch
  if pure addition and no vuln effects: return Vuln

  retry with O3 signatures (if available)
  else return Vuln
```

## Key files

- `react/src/main.rs` (test harness, bitcode/diff wiring)
- `ir-analysis/src/lib.rs` (IRAnalysis, IRAnalysis2, test logic)
- `ir-analysis/src/emulator.rs` (effect extraction by symbolic execution)
- `ir-analysis/src/effect.rs` (effect definition, matching, refinement)
- `source-analysis/src/lib.rs` (diff parsing and function detection)
