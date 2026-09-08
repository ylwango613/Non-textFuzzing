Based on my complete reading of the 256-line file and cross-referencing with the headers and callers, here is my assessment:

**Analysis summary:**

- `ff_xvid_idct_mmi()`: Pure MIPS MMI assembly IDCT. All block accesses are fixed offsets (`0*16` to `7*16+8` = bytes 0–120) within a standard 128-byte 8×8 `int16_t` block. No user-controlled sizes.
- Static tables are compile-time constants: `tab_i_04_mmi` (256 bytes), `rounder_0` (64 bytes), `tg_1_16` (32 bytes). Maximum assembly offsets are `56+64*3=248`, `8*7=56`, and `3*8=24` — all within bounds.
- `ff_xvid_idct_put_mmi` / `ff_xvid_idct_add_mmi`: Simple wrappers that delegate to `ff_put_pixels_clamped_mmi` / `ff_add_pixels_clamped_mmi`. No allocation or size computation here.
- No `av_malloc`, `memcpy`, or external field read in this file.
- `block` always comes from the caller's pre-allocated 8×8 DCT block (part of `MpegEncContext`), not from a container-controlled size field.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
