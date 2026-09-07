After reading the complete `error.cpp` (195 lines) and `error.hpp` (299 lines) in full, here is the analysis:

**`error.cpp` — full code review:**

- **`errList` array (lines 15–95)**: `constexpr std::array` of string literals. `static_assert` ensures size exactly matches `ErrorCode::kerErrorCount`. No out-of-bounds risk.
- **`Error::setMsg()` (lines 167–192)**: Uses `errList.at(...)` — bounds-checked accessor that throws `std::out_of_range`, never causes memory corruption. String substitution uses `std::string::find()` + `std::string::replace()`, both safe standard-library operations.
- **`LogMsg::~LogMsg()` (lines 110–113)**: `handler_` is null-checked before dereferencing; `os_.str().c_str()` temporary lives until the full expression (the function call) completes — no dangling pointer.
- **`LogMsg::defaultHandler()` (lines 135–153)**: Only writes to `std::cerr`, no unsafe formatting.
- **Error template constructors (error.hpp lines 242–262)**: Use `toBasicString<char>(arg)` which internally uses `std::ostringstream` — safe.

**No attacker-controlled external data** (file bytes, IFD fields, IPTC records, etc.) flows through this file. It is purely internal error-message infrastructure using type-safe C++ standard containers and no raw pointer arithmetic, `memcpy`, `malloc`, or unsafe format strings.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
