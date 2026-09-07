I have now fully read `tif_thunder.c` (189 lines), all related headers (`tiffiop.h`, `tiffio.h`, `tif_dir.h`), and traced the complete call chain through `tif_read.c` and `tif_dirread.c`.

**Summary of analysis by group:**

**Group 1 — SETPIXEL macro (lines 59–68):** Only writes when `npixels < maxpixels`; advances `op` only on odd pixels (lower-nibble fill). No way to exceed the output buffer.

**Group 2 — THUNDER_RUN case (lines 104–122):** Two sub-paths:
- *Odd npixels*: writes byte k then advances `op`; the subsequent fill-loop runs `ceil((n-1)/2)` writes bounded by the same `npixels+n < maxpixels` check. I verified algebraically (both n-even and n-odd sub-cases) that the last written byte is always ≤ `(maxpixels−1)/2` (the last valid buffer byte).
- *Even npixels*: loop writes `ceil(n/2)` bytes, again provably bounded when `old_npixels+n < maxpixels`.
- `*--op &= 0xf0` when `n == -1` backs up exactly one byte, always a valid address.

**Group 3 — THUNDER_2BITDELTAS / THUNDER_3BITDELTAS / THUNDER_RAW (lines 123–139):** All use SETPIXEL which self-guards; extra SETPIXEL calls beyond `maxpixels` are silently no-ops.

**Group 4 — ThunderDecodeRow (lines 155–168):** Potential infinite loop when `tif_scanlinesize = 0`, but `TIFFReadDirectory` (tif_dirread.c:801) explicitly checks for and rejects zero scanline size, so that path is unreachable in practice. No memory corruption.

**Group 5 — Type conversion (uint32 → tsize_t/int32):** `td_imagewidth > INT32_MAX` makes `maxpixels` negative; the outer-loop condition `npixels < maxpixels` (0 < negative) is immediately false, and `ThunderDecode` returns error without any write.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
