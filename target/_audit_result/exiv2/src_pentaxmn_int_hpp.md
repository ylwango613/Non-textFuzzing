After a complete multi-pass analysis of `pentaxmn_int.hpp` and its full implementation in `pentaxmn_int.cpp` (1481 lines), I traced all data flows and potential memory-safety issues:

**Batch 1 (lines 0–600):** Tag constant tables only — no executable code, no risk.

**Batch 2 (lines 600–1000):** `printDate`/`printTime`/`printShutterCount`/`printBracketing` — these access `value.toInt64(n)` / `toUint32(n)` using `std::vector::at(n)` which throws `std::out_of_range` on OOB. Every call site is wrapped in the `try { fct(os, value(), pMetadata); } catch (const std::out_of_range&) { os << "Bad value"; }` block in `exif.cpp:192`. No memory corruption.

**Batch 3 (lines 1000–1260):** `resolveLens0x3ff`, `resolveLens0x8ff`, `resolveLens0x319`, `resolveLens0x32c` — these use the pattern `auto td = Exiv2::find(pentaxLensType, lensID); td[index].label_`. I verified: the hardcoded `lensID` values (0x3ff/0x8ff/0x319/0x32c) are always present in the array so `find` never returns `nullptr`. The maximum `index` values (8/7/6/1 respectively) are within the contiguous blocks of matching entries (11/8/7/7 entries). All guard conditions (`lensInfo->count() < 5` etc.) and access-time exceptions are caught by the function-level `try { ... } catch (...) {}` blocks.

**Batch 4 (lines 1260–1481):** `printLensType` and `tagInfo_` table — lookups through `Exiv2::find` always null-checked; table access safe.

**Integer arithmetic:** `printCombiTag` shift expressions are capped to 24 bits (count ≤ 4, enforced by template), no overflow.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
