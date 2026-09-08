The file `metadatum.cpp` is 41 lines and contains only:
1. Virtual destructors
2. `Key::clone()` — pure delegation to virtual `clone_()`
3. `Metadatum::print()` — writes to `std::ostringstream`
4. `Metadatum::toUint32()` — converts `int64_t` to `uint32_t` with two explicit `enforce()` range-checks (lower-bound and upper-bound)
5. Two pure comparison predicates used for sorting

There are no raw pointer operations, no buffer allocations, no array indexing, no memcpy, and no integer arithmetic that bypasses the bounds checks. The `toUint32()` range checks are correct: `uint32_t` bounds are promoted to `int64_t` before comparison, so negative values and values > 4294967295 both throw.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
