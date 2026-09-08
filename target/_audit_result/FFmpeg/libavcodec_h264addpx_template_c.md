**Analysis summary:**

The file `h264addpx_template.c` is 73 lines containing two functions: `ff_h264_add_pixels4` and `ff_h264_add_pixels8`. Both are simple DSP pixel-accumulation routines templated over `BIT_DEPTH`.

Key findings from the audit:

1. **`memset` bounds** (`sizeof(dctcoef) * 16` / `sizeof(dctcoef) * 64`): Correct. The `sl->mb` buffer is explicitly declared as `int16_t mb[16*48*2]` with the comment "as a DCT coefficient is int32_t in high depth, we need to reserve twice the space" — so in high-bit-depth mode the 64-byte `memset` is safe within a 3072-byte buffer.

2. **Type punning / alignment**: Casting `int16_t*` → `int32_t*` (dctcoef in >8-bit mode) is safe because the buffer is `DECLARE_ALIGNED(16, ...)`, satisfying int32_t alignment.

3. **`stride /= sizeof(pixel)`**: No OOB possible — stride is the frame's linesize, not attacker-controlled at this level.

4. **Access patterns (`dst[0..3]`, `src[0..3]` etc.)**: Hardcoded 4×4 / 8×8 block patterns, no attacker-controllable index.

5. **No direct bitstream parsing** in this file — both `_dst` and `_src` are internal codec state (decoded coefficients within `sl->mb`, frame data within `cur_pic`) validated before reaching these functions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
