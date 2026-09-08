Based on my complete analysis of `minoltamn_int.hpp` (137 lines, declarations only) and its full implementation `minoltamn_int.cpp` (2038 lines), here are my findings:

**Summary of analysis:**

1. **`resolvedLens` / `td[0]` null-deref risk** (line 1657): `Exiv2::find` can return null, but all six callers hardcode lens IDs (`0x1c`, `0x29`, `0x34`, `0x80`, `0xff`, `0xffff`) that are verified to exist in the compile-time `minoltaSonyLensID` table. Not exploitable.

2. **`rtrim` unsigned wrap** (line 1625): `npos + 1 = 0` (well-defined unsigned wrap), causing `s.erase(0)` on an all-whitespace string — erases everything, which is correct behavior. No memory safety consequence.

3. **`tokens.at(index - 1)` OOB** (line 1658): Caught by `catch (...)` blocks in all callers; `std::vector::at()` throws `std::out_of_range`. No memory corruption.

4. **Print functions** (lines 294–356, 684–693): Only do arithmetic on `value.toInt64()` and format to `std::ostream`. No raw buffer access.

5. **All TagInfo/TagDetails tables**: Compile-time constants; no runtime memory operations.

6. **No `memcpy`, `memmove`, `DataBuf`, or raw pointer arithmetic** anywhere in this file.

7. **`getKeyLong` division** (lines 1792, 1804): Protected by `if (focalLength > 0)` guards; no divide-by-zero reaching memory.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
