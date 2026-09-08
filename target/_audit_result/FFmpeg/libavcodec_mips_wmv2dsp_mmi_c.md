After a thorough line-by-line review:

**Group 1 (lines 37–96): `wmv2_idct_row_mmi` / `wmv2_idct_col_mmi`**  
Static arithmetic on `b[0..7]` (row) and `b[0..56 step 8]` (col). All indices are compile-time constants; `b` is always a slice of the 64-element `int16_t block[]`. Signed-int arithmetic at max coefficient values (`181 * (a1-a5+a7-a3)`) can overflow 32-bit `int` (UB), but the result is written back only into the same block array — no memory corruption.

**Group 2 (lines 98–213): `ff_wmv2_idct_add_mmi` / `ff_wmv2_idct_put_mmi`**  
Inline assembly loads `block[0..31]` in the low loop, advances `block` by `0x40` bytes, then loads `block[32..63]` in the high loop — exactly 64 int16_t elements, matching the caller-allocated buffer. Dest receives 8 rows × 8 bytes each (advancing by `line_size` each row), which is the standard 8×8 IDCT pattern for a properly allocated AVFrame. `line_size` comes from FFmpeg's frame allocator (not directly from the bitstream), and `packushb` clamps output to [0,255]. No allocation site, no dynamic sizing, no memcpy with attacker-controlled length.

**Calling context (wmv2dsp_init_mips.c):** Both functions are registered as `c->idct_add` / `c->idct_put`. Their inputs (`dest`, `line_size`, `block`) are prepared by the codec's MB loop in caller code, not directly from raw bitstream fields. No exploitable path from crafted file data to a memory-safety violation originates in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
