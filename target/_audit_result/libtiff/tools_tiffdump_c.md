I've now read all 719 lines of `tiffdump.c` in full and queried all relevant types and helper signatures. Let me record my group-by-group analysis:

**Lines 1–135 (main, arg parsing):** `diroff` is a `uint32`, `maxitems` a `uint32` from `strtoul`. No unsafe casts or buffer access.

**Lines 190–237 (dump):** Header read is size-checked (`sizeof(hdr)`). IFD loop counter `i` is unsigned; if `nextdiroff` creates a cycle the loop is infinite (DoS only, not memory-safety). `diroff` comparison uses `off_t`. Safe.

**Lines 266–372 (ReadDirectory — the core):**
- Line 288: `_TIFFmalloc(dircount * sizeof(TIFFDirEntry))`. `dircount` is `uint16` (max 65535), `sizeof(TIFFDirEntry)=12`; product ≤ 786 420 — fits in `tsize_t` (int32). Safe.
- Line 293: `read(fd, dir, dircount*sizeof(*dp))` — same product, well within range.
- Line 322: `space = TIFFSafeMultiply(int, dp->tdir_count, datawidth[dp->tdir_type])`. The macro checks `(int)((v*m)/m) == (int)v` using uint32 arithmetic; for all `m ∈ {0,1,2,4,8}` I verified every wraparound scenario returns 0 or a negative `space` value, which is caught by `if (space <= 0)`.
- Line 350: `_TIFFmalloc(space)` — only reached when `space > 4`, so a valid positive int32.
- Lines 353-359: `PrintData` is called with `min(count, maxitems)` items; since `dp->tdir_count > maxitems` in that branch, the buffer of `dp->tdir_count * width` bytes covers `maxitems * width` bytes. Safe.

**Lines 638–675 (TIFFFetchData):**
- Line 644: `cc = dir->tdir_count * w` — raw multiplication. However, `TIFFFetchData` is only called from the `else` branch where `space = dp->tdir_count * datawidth[dp->tdir_type] > 4` was already validated via `TIFFSafeMultiply`. Same multiplicands, so `cc = space` (same positive value). Buffer allocated with `space` bytes; `read(fd, cp, cc)` reads exactly `space` bytes. Safe.
- Line 663: `TIFFSwabArrayOfLong((uint32*)cp, 2*dir->tdir_count)` for RATIONAL — `dir->tdir_count ≤ INT_MAX/8 = 268 435 455`, so `2*dir->tdir_count ≤ 536 870 910` — no overflow, accesses exactly the allocated buffer.

**Lines 514–633 (PrintASCII, PrintData):** All type-casts to `uint16*`/`uint32*`/`float*`/`double*` are from `_TIFFmalloc`-aligned memory. Loop bounds equal the validated `count`. Safe.

**Stack buffer at line 340 (`unsigned char data[4]`):** Only reached when `space ≤ 4`; all element widths × counts in that branch are ≤ 4 bytes. `PrintData` never reads beyond 4 bytes.

**`typeshift[14]` / `typemask[14]`:** Indices 0–13 match enum values 0–TIFF_IFD=13. Initialized but never actually read back in any expression — dead arrays, no OOB risk.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
