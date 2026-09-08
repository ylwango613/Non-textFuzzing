**Analysis complete.**

`sigmamn_int.cpp` is a 117-line file containing:
1. A `constexpr` static tag-info array — no dynamic memory operations.
2. Three `print*` functions that operate purely on `std::string` values.

Key observations per function:

- **`printStripLabel` (lines 71–79)**: `v.at(pos + 1)` at line 74 will throw `std::out_of_range` when `:` is the last character of the string (i.e., `pos == v.size()-1`). This is a DoS via uncaught exception, **not** a memory-safety vulnerability — `std::string::at()` performs bounds checking and throws; there is no buffer overread or heap corruption.
- **`print0x0008` / `print0x0009` (lines 81–115)**: Both guard `v.empty()` before calling `v.front()`. Safe.
- No `DataBuf` allocations, no `memcpy`/`std::copy`, no raw pointer arithmetic, no integer overflow paths, no recursion.

The file contains no memory-corruption-class vulnerabilities.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
