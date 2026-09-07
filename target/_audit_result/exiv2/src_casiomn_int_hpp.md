**Analysis Summary:**

**`casiomn_int.hpp`** (69 lines): Pure class declarations for `CasioMakerNote` and `Casio2MakerNote` — no code, no memory operations.

**`casiomn_int.cpp`** — Detailed per-section analysis:

**Section 1 (lines 1–146): Tag tables** — All `constexpr TagInfo` arrays. Static read-only data, no dynamic allocation, no runtime memory operations.

**Section 2 (lines 147–149): `CasioMakerNote::print0x0006`** — Single `value.toInt64() / 1000.0`. No buffer access.

**Section 3 (lines 151–179): `CasioMakerNote::print0x0015`** — Builds `std::vector<char> numbers` via `push_back(l)`. Bounds checks verified:
- `numbers.size() >= 10` guards indices `[0]...[9]` ✓
- `numbers.size() == 12` guards indices `[10]...[11]` ✓
- `value_.at(n)` in `StringValueBase::toInt64` uses bounds-checked access ✓

**Section 4 (lines 346–446): Casio2 tag tables** — Same as Section 1: constexpr only.

**Section 5 (lines 448–472): `Casio2MakerNote::print0x2001`** — Identical pattern to `print0x0015`:
- `numbers.size() >= 10` guards indices `[0]...[9]` ✓

**Section 6 (lines 474–479): `Casio2MakerNote::print0x2022`** — Single `value.toInt64()` check and division. No buffer access.

**Data flow check:** `StringValueBase::toInt64(n)` returns `static_cast<signed char>(value_.at(n))`, so the `numbers.push_back(l)` narrowing conversion from `int64_t` to `char` always stays within `char` range (already cast to signed char at source). No UB from narrowing.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
