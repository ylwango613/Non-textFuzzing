**Complete analysis summary:**

**Batch 1 (full file, lines 1–499):**

- `ras_gethdr`: Reads exactly 8×4=32 bytes into a fixed struct. No allocation, no OOB risk.
- `ras_decode`: Validates `magic`, `width>0`, `height>0`, `0<depth≤32`. Then calls `jas_safe_size_mul3(width, height, ceil(depth/8))` — which correctly guards against 64-bit overflow — followed by a `max_samples` (64 MB) cap. The `RAS_ROWSIZE * height` for `TYPE_OLD` is assigned only to `hdr.length`, which is never used for allocation.
- `ras_getcmap`: `numcolors = 1 << hdr->depth` (int). For depth 1–8 this is 2–256; depth 9–30 gives numcolors > 256 → `return -1`. For depth 31–32 the shift is UB, but common x86 outcomes (INT_MIN or 0–1) all force `return -1` through the subsequent maplength check (any positive maplength satisfies `maplength > 3 * INT_MIN` or `maplength > 0`). Within the valid depth ≤ 8 path: `actualnumcolors = maplength/3 ≤ numcolors ≤ 256`; `cmap->data` is `int[256]`, so `cmap->data[j]` (j < actualnumcolors ≤ 256) is always in bounds.
- `ras_getdatastd`: Pixels read into `jas_matrix` allocated to image width. `pad` is used only as a boolean (read ≤1 extra byte). Bit-buffer arithmetic is safe for the constrained depth range. `cmap = 0` discards the colormap anyway.
- `jas_safe_size_mul3`: Correctly propagates overflow checks through two multiplications.
- With `max_samples = 64M` and depth ≤ 32, max `width * depth` ≤ 512M < INT32_MAX, so `RAS_ROWSIZE` arithmetic never overflows within the admitted input range.
- No `memcpy`/`memmove` with file-controlled size. No fixed-size stack buffers indexed by file data. No UAF patterns.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
