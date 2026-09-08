I have now read the entire 3302-line file across multiple passes, plus the key utility implementations (`DataBuf::c_data`, `DataBuf::c_str`, `DataBuf::read_uint8`, `DataBuf::resize`). My analysis:

**Pass 1 (lines 1–500)**: Pure compile-time `constexpr` tag tables — `GroupInfo`, `TagDetails`, `TagInfo` arrays. No runtime allocation, no external data parsed here.

**Pass 2 (lines 500–1800)**: More `constexpr` tag descriptor arrays (IFD0, Exif, DNG tags). Entirely static data.

**Pass 3 (lines 1800–2600)**: GPS/MPF/IOP/MN tag tables, simple lookup functions (`tagList`, `tagInfo`, `isMakerIfd`, `isExifIfd`). No raw buffer operations.

**Pass 4 (lines 2600–3302)**: All the actual function implementations — `printUcs2`, `printDegrees`, `printExifVersion`, `printVersion`, `print0x0007`, `print0x9204`, `exposureTime`, etc.

**Key findings per function:**

- `printUcs2` (line 2734): Allocates `DataBuf buf(value.size())` from already-parsed `Value`, fills with `value.copy`, then strips. When `buf` becomes empty (e.g., 1-byte input), `buf.c_str()` returns `nullptr` (confirmed from `types.cpp:197` — `c_data` returns null when `pData_.empty()`). Then `std::string(nullptr, 0)` is called. This is **technically UB** (C++ standard requires pointer to be non-null even for n=0), but never dereferences the null pointer in any major stdlib implementation, and count=0 means no write occurs. Not a practical memory safety vulnerability.

- `printDegrees` (line 2700): Division guarded by `min.second <= 0` check; multiplication overflow guarded by `rem <= INT32_MAX/60` check. Safe.

- `print0x0007` (line 2867): `enforce<std::overflow_error>(std::isfinite(t), ...)` guards against infinity/NaN. Safe.

- `print0x9204` (line 3050): `bias.first == INT32_MIN` guarded before `std::abs`. Safe.

- `printExifVersion` (line 3253): Checks `value.size() == 4` before accessing 4 elements; string_view size check in `printVersion` before indexing. Safe.

- All `read_uint8` calls occur with bounds verified by the `buf.size() >= 2` loop guard. The `read_uint8` implementation itself throws on out-of-range.

**Scope note**: This file does not contain any IFD parsing, count×typeSize allocation math, or raw file offset arithmetic. Those are in `tiffvisitor.cpp`, `tiffcomposite.cpp`, `exif.cpp` etc.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
