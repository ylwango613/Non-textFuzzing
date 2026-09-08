All scratch buffers are stack-allocated with fixed compile-time sizes. Complete analysis summary:

**Group 1 — 8×8 functions (lines 232–370):** All load/store offsets are compile-time constants (0–112 bytes for 8×16-byte rows). No dynamic sizes.

**Group 2 — 16×16 functions (lines 372–734):** `out_arr[16*16]` = 512 bytes. `vp9_idct16_1d_columns_lsx` writes at most to byte 255 from its `output` base. For the second call (`i=1`, output = out+256 bytes), max store at byte 511. Array exactly 512 bytes. Boundary check: ✓

**Group 3 — 32×32 functions (lines 736–1368):** `out_arr[32*32]` = 2048 bytes, `tmp_buf[8*32]` = 512 bytes, `tmp_eve_buf[16*8]` = 256 bytes, `tmp_odd_buf[16*8]` = 256 bytes.
- Max load in `vp9_idct8x32_column_odd_process_store`: `tmp_buf + 31*64 = 1984`, + 16 bytes = 2000 bytes from pointer. For i=3: base is `out_arr+48 bytes`, 48+2000 = 2048 — still within 2048-byte array.
- Max write in `vp9_idct_butterfly_transpose_store` to `tmp_buf`: offset `48 + 32*14 = 496` + 16 = 512 bytes, exactly matching `tmp_buf[8*32]` = 512 bytes.
- Max write to `tmp_eve_buf`: `14*16 + 16 = 240` + 16 = 256 bytes ✓
- Max write to `tmp_odd_buf`: `12*16 + 3*16 = 240` + 16 = 256 bytes ✓
- Max write to `output` in `vp9_idct_butterfly_transpose_store`: offset `48 + 32*14 = 496` + 16 = 512 bytes. For i=3: out_ptr + 768 int16_ts + 511 = 2047 bytes within 2048 ✓

**Key finding:** This file contains only fixed-size SIMD inverse-DCT routines operating on pre-allocated coefficient blocks. No `malloc`/`realloc`, no `memcpy` with untrusted lengths, no extradata processing, no container-derived sizes. All buffer accesses are statically bounded by the transform block dimension (8, 16, or 32) and verified to be within their respective stack allocations.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
