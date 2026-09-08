All `Value::toInt64(n)`, `toUint32(n)`, `toFloat(n)`, and `toRational(n)` implementations uniformly use `value_.at(n)` — the C++ bounds-checked accessor that throws `std::out_of_range` on an out-of-bounds index. There is no raw `operator[]` access in any of these code paths.

**Summary of analysis across the entire file (3589 lines):**

- **printBarValue** (line 191): The guard `value.count() >= 9` permits access to index `6+3=9`, which is OOB when count==9. However, `value_.at(9)` throws `std::out_of_range`—not memory corruption. This is a potential DoS through an unhandled exception, outside the memory-safety scope.
- **print0x0088 / Nikon1 & Nikon3**: All `nikonFocuspoints[i]` accesses are within the 11-element bound (indices 0–10). Bitmask loops are correctly bounded.
- **printLensId** (line 3155): `byte raw[8]` is written only at indices 0–7 (loop 0–6, then index 7 explicitly). Safe.
- **EXV_PRINT_TAG** calls with computed integer values (e.g., `v0 & 0x0F`): Uses `Exiv2::find()` linear search—no direct indexing.
- **No heap allocations**, no `memcpy`/`memmove`, no pointer arithmetic, no recursion anywhere in the file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
