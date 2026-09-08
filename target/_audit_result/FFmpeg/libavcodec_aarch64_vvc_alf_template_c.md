After reading the full file and tracing all related macros, buffer sizes, assembly implementations, and call chains, my findings are:

**Key analysis performed:**

1. **`ALF_ALIGN_BY_4` macro in SME2 path (line 250)**: For `width` near `INT_MAX`, `4*((width-1)>>2u)+4` can overflow signed int. But VVC imposes level-dependent picture dimension limits (max ~16384) which are validated by the bitstream parser before reaching this code — the overflow is unreachable from any real input.

2. **Filter/clip pointer advancement in neon path (lines 96–97)**: The neon loop steps `x += 2*ALF_BLOCK_SIZE = 8` and advances filter/clip by `2*ALF_NUM_COEFF_LUMA = 24` per step — identical net consumption to the scalar path (`x += 4`, advance 12). For widths not divisible by 8, the neon kernel writes 8 pixels per call while only 4 may be "valid", but this only writes into stride padding, not outside the allocated frame buffer.

3. **Gradient buffer type cast (line 241–242)**: `gradient_tmp` is allocated as `int32_t[ALF_GRADIENT_SIZE * ALF_GRADIENT_SIZE * ALF_NUM_DIR]` = 69,696 bytes. The neon path uses it as `int16_t[]`. The assembly (`ff_alf_classify_grad_neon`) writes exactly 69,696 bytes (verified: for max width+4=132, 132 rows × 528 bytes/row). Buffer size matches exactly — no overflow.

4. **`ff_alf_classify_grad_10_neon` empty body (alf.S line 493–494)**: The 10-bit function is an empty stub — correctness bug (wrong output for 10-bit VVC) but no memory corruption.

5. **Source pointer underflows (p6 = src − 3*stride)**: Handled correctly — `alf_filter_luma` operates on a padded copy (via `alf_prepare_buffer`) with `ALF_BORDER_LUMA` rows of border, so negative-offset accesses always land in valid padding.

6. **`strides` packing for SME2 (line 268)**: `((uint64_t)src_stride << 32u) | (uint64_t)dst_stride`. For any valid VVC frame, strides fit in 32 bits (max ~32768 bytes), so no truncation corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
