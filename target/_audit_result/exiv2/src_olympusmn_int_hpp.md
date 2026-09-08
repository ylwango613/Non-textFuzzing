I have now read the complete `olympusmn_int.hpp` (118 lines) and the full `olympusmn_int.cpp` (1673 lines) in three batches. I also traced every call into `Value::toInt64()`, `DataValue`, `StringValueBase`, and `ValueType<T>`. Here is what each layer shows:

**Tag info arrays** (lines 143–1133): Large `constexpr` tables. All read-only compile-time data — no heap involvement.

**Print functions** (lines 1136–1671):  
- Every function validates `value.count()` and/or `value.typeId()` before accessing any index, e.g. `if (value.count() != 3 || value.typeId() != signedShort)` → early return.  
- All index accesses go through `value.toInt64(n)`, which in every concrete `Value` subclass (`DataValue`, `StringValueBase`, `ValueType<T>`) delegates to `std::vector::at(n)` — bounds-checked, throws `std::out_of_range`, no silent OOB read.  
- No `DataBuf` allocation, no `memcpy`/`memmove`, no integer arithmetic on untrusted sizes, no pointer arithmetic, no recursion.

**`printGeneric`**: Declared in the header (line 98) but never implemented in `.cpp` and never referenced in any `TagInfo` entry. Dead declaration — not a call-site vulnerability.

**Logic oddity in `printCs0x0301`** (line 1656–1667): the E3/E30 branch can fall through the loop without returning, causing a duplicate integer print. This is a display bug, not a memory-safety issue.

No externally-triggerable memory-safety vulnerability was found in the audited files.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
