The file `metadatum.hpp` is 295 lines — fully read in one pass. Its companion `metadatum.cpp` is also fully read. The analysis is complete:

**Group 1 — `metadatum.hpp` (all 295 lines)**

- `Key` class (lines 30–94): pure abstract base, all pure virtual methods, no memory operations whatsoever.
- `Metadatum` class (lines 105–272): pure abstract interface. The only non-virtual concrete methods declared here are `print()` (line 136) and `toUint32()` (line 217). `copy()` (line 148) is pure virtual — it is only declared, not implemented.
- Documentation comment on `copy()` (lines 143–147): "The user must ensure that the buffer has enough memory. Otherwise the call results in undefined behaviour." This is API documentation about the caller's responsibility, not an implementation flaw in this file.

**Group 2 — `metadatum.cpp` (companion implementation)**

- `print()` (line 19–23): delegates to virtual `write()` via `ostringstream` — fully safe.
- `toUint32()` (lines 25–30): calls `toInt64(n)` then enforces both `>= INT32_MIN` and `<= UINT32_MAX` via `Internal::enforce()`, which throws `kerCorruptedMetadata` on violation. Properly range-checked, not exploitable.
- `cmpMetadataByTag` / `cmpMetadataByKey` (lines 32–38): trivial tag/key comparisons, no memory operations.

**Summary of findings**: The file under audit (`metadatum.hpp` + `metadatum.cpp`) is a pure abstract interface layer. It contains no buffer operations, no allocations, no integer arithmetic on externally-controlled data, and no raw pointer dereferences. All methods are either pure virtual declarations or trivially safe implementations. No memory safety vulnerabilities are present in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
