Now I have full context. Let me analyze all the code carefully:

**hqxdsp.c analysis:**
- `idct_col`: accesses `blk[0*8]` through `blk[7*8]` (indices 0,8,16...56), all within a 64-element block. Safe.
- `idct_row`: accesses `blk[0]` through `blk[7]`, safe.
- `hqx_idct_put`: accesses `block[j + i*8]` for j=0..7, i=0..7 → max index 63. `dst[j]` for j=0..7 per row. `dst += stride >> 1` advances correctly.

**Caller (hqx.c) analysis:**
- Frame size validated with `av_image_check_size` before buffer allocation
- Slice offsets validated at lines 410-413 before use in `init_get_bits8`
- `decode_block`: `pos > 63` check before `ff_zigzag_direct[pos]` access (line 173)
- MB coordinates bounded by `mb_w`/`mb_h` derived from validated image dimensions
- `put_blocks` writes at most `coded_width * 2` bytes per row, within the allocated frame

**Integer arithmetic in idct_col:** `s3 * 19266U` uses intentional unsigned wrap-around for fixed-point IDCT — standard technique, not a bug.

**Division-by-zero concern in decode_slice:** `grp_v_rest` and `grp_h_rest` could be 0 when dimensions are perfectly divisible, leading to SIGFPE. However, this is a DoS without memory corruption, excluded per audit scope.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
