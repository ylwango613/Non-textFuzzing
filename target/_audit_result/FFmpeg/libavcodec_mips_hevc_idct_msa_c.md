After a full two-pass read of all 1026 lines and verification of:

- The `HEVC_IDCT16x16_COL` macro's `buf_ptr`/`ptr0`/`ptr1` arithmetic across all 4 loop iterations and both outer loop passes against `buf[256]`
- The `int32_t tmp_buf[8*32+15]` alignment trick in `hevc_idct_8x32_column_msa` (worst-case `tmp_buf_ptr = tmp_buf+0`, max access index 120, buffer 271 ✓)
- The `int16_t tmp_buf[8*32+31]` in `hevc_idct_32x32_msa` (worst-case `tmp_buf_ptr = tmp_buf+0`, max access index 255, buffer 287 ✓)
- All `ST_SH`/`ST_SW` writes in the 32-row loop of `hevc_addblk_32x32_msa` against a 32×32 pixel `dst` buffer
- The `hevc_idct_dc_*` functions' loop/stride arithmetic for 16×16 and 32×32 matrices
- All coefficient array reads (max index confirmed < 1024 for 32×32)

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
