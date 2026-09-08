With the full picture from the header files and tiff_common.c, I can complete my analysis.

**Group 1 (lines 1–560) — parsing core:**
- `count` is `int`, assigned from `ff_tget_long` (returns `unsigned`). The check `count >= INT_MAX/8U` at line 508 uses unsigned comparison (int is widened to uint), correctly rejecting all values ≥ 268435455 including negative-wrapped uint32 values. ✓
- `exif_sizes[entry->type] * entry->count` at line 275: max product is 268435454×8 = 2147483632, fits in both 32-bit and 64-bit size_t. ✓
- `exif_sizes[]` indexed with validated type (1–13). ✓
- `av_mallocz(entry->count + 1)` for STRING: count < 268435455, so +1 ≤ 268435455, no overflow. ✓
- `av_calloc` handles overflow internally. ✓

**Group 2 (lines 561–642) — IFD list parsing:**
- `entries = ff_tget_short(...)` — 16-bit, max 65535 × 12 = 786420, fits in int/uint32. ✓
- `entries > 4096` hard limit. ✓
- `av_size_mult` used for `required_size`. ✓
- `ff_tget_long` next-IFD pointer stored in `int ret`: values >INT_MAX rejected at line 636 (`ret < 0`). This means IFDs with large offsets (>2GB) are silently dropped — a correctness issue, not a security one.

**Group 3 (lines 643–962) — free, write, clone, API:**
- `exif_clone_entry` for `AV_TIFF_STRING`: `src->count + 1` — if count were UINT32_MAX this wraps to 0, causing an under-allocation. But count coming from parsing is bounded to <268435455; only reachable if count set via API with `av_exif_set_entry()` which takes unchecked uint32_t. API misuse, not from parsing external files.
- `exif_get_ifd_size` at line 688: `entry->count * exif_sizes[entry->type]` uses uint32_t × size_t; on 64-bit no overflow for values up to UINT32_MAX×8 ≈ 34GB. On 32-bit: count from parsing is < 268M, × 8 < INT_MAX, no overflow.
- `av_exif_parse_buffer` `AV_EXIF_T_OFF` path: `AV_RB32(buf) + 4` as uint32_t arithmetic can wrap to 0, causing a re-parse from offset 0. Not memory corruption — `ff_tdecode_header` would reject the invalid TIFF magic.

**Recursion depth guard at line 489 (`depth > 3`)** prevents stack exhaustion.

All critical memory-safety paths in the parser are covered by appropriate bounds checks. No externally-triggerable memory safety vulnerability found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
