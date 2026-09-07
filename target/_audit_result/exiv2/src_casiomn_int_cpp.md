I have now completed a thorough analysis of the entire `casiomn_int.cpp` file (481 lines) and all relevant calling context.

**Group 1 — Lines 1–145 (TagDetails and TagInfo tables):** Pure `constexpr` static data. No runtime memory operations.

**Group 2 — `print0x0006` (lines 147–149):** Reads a single scalar via `value.toInt64()`, formats with `stringFormat`. No buffers, no indexing.

**Group 3 — `print0x0015` / `print0x2001` (lines 151–179, 448–472):** Both functions follow the same pattern:
- Iterate `value.size()` times calling `value.toInt64(i)` — internally uses `value_.at(n)` (bounds-checked).
- Collect non-zero bytes into `std::vector<char> numbers` via `push_back`.
- Access `numbers[0..9]` is guarded by `numbers.size() >= 10`.
- Access `numbers[10..11]` is guarded by `numbers.size() == 12`.
- No `DataBuf`, no `memcpy`, no attacker-controlled allocation size. No OOB possible.

**Group 4 — `print0x2022` (lines 474–479):** Scalar read only. No memory hazards.

**`Casio2MnHeader::read`:** Validates `size >= sizeOfSignature()` (6 bytes) and `memcmp` against a fixed signature before `alloc(sizeOfSignature())`. Allocation size is a compile-time constant, not attacker-controlled.

After exhaustive analysis of all code paths in the file and the relevant portions of the call chain (`Value::toInt64`, `StringValueBase::toInt64`, `DataValue::toInt64`, `Casio2MnHeader::read`), there are no externally-triggerable memory-safety vulnerabilities in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
