After thoroughly analyzing `tiff_common.c` and tracing all calling contexts in `tiff.c` and `exif.c`, here is my complete assessment:

**Group 1 — `ff_tadd_string_metadata` (lines 142–159)**
- `av_malloc(count + 1)`: when `count = INT_MAX`, the `int + int` addition overflows to `INT_MIN`; converting `INT_MIN` to `size_t` on a 64-bit system yields ~18 EB, so `av_malloc` returns `NULL` → safe ENOMEM path.
- The bounds check `bytestream2_get_bytes_left(gb) < count` is a signed `int < int` comparison; for `count = INT_MAX` to pass it, the stream would need exactly `INT_MAX` (~2 GB) bytes remaining — impractical.

**Group 2 — `ff_tadd_doubles_metadata` (lines 100–118) / `ff_tadd_shorts_metadata` (lines 121–139)**
- `av_bprint_init(&bp, 10 * count, 100 * count)`: signed integer overflow (UB) for large `count` values ≤ `INT_MAX/8` but >`INT_MAX/10`. The overflow affects only `av_bprint` initialization size, not a data-buffer heap allocation; `av_bprint` handles allocation failure gracefully — no heap corruption.

**Group 3 — `ff_tdecode_header` ifd_offset truncation (lines 181–182)**
- `*ifd_offset = ff_tget_long(gb, *le)` assigns an `unsigned` into `int *`; values > `INT_MAX` produce negative offsets.
- All callers pass this to `bytestream2_seek(..., SEEK_SET)`, which `av_clip`s to `[0, buffer_end - buffer_start]` — safe.

**Group 4 — `ff_tread_tag` type_sizes multiplication (line 209)**
- `type_sizes[*type] * (*count)` can overflow `unsigned` for extreme `*count`, but the outer `*count > 4` check ensures a seek happens for all large counts regardless — no control-flow mistake.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
