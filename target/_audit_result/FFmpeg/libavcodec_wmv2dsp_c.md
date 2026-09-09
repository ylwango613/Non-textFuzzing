After fully analyzing `wmv2dsp.c` and its call chain:

**Summary of analysis:**

1. **`wmv2_idct_row`** (L35-63): Reads/writes `b[0]`–`b[7]`. Called with `block + i` where `i ∈ {0,8,16,...,56}` — always 8 contiguous elements of the 64-element block. No OOB.

2. **`wmv2_idct_col`** (L65-94): Accesses `b[8*k]` for `k=0..7` (indices 0,8,16,...,56). Called with `block + i` where `i=0..7`, so max index = 7+56=63. Exactly within the 64-element block. No OOB.

3. **`wmv2_idct_add_c` / `wmv2_idct_put_c`** (L96-140): Both iterate 8 rows, advance `dest` by `line_size` (from `AVFrame.linesize[]`, computed during allocation — not directly bitstream-controlled), and consume exactly 64 elements of `block` (the fixed-size `int16_t block[64]` passed from the codec). No OOB.

4. **Arithmetic**: The `181U * (...)` at L51-52 and L81-82 uses intentional unsigned multiplication to avoid signed-overflow UB — a well-known IDCT implementation technique. Results remain deterministic and are clamped by `av_clip_uint8` before write-back. No exploitable consequence.

5. **`ff_wmv2dsp_init`** (L142-154): Only sets function pointers and calls `ff_init_scantable_permutation` — no memory allocation or size-dependent copy.

All array accesses are on fixed-size 8×8 (64-element) blocks. No dynamic allocation, no user-controlled sizes, no unchecked strides from the bitstream reach these functions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
