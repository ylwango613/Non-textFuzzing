Based on my complete analysis of the file and its full dependency chain, here is my assessment:

**Analysis summary:**

1. **`apv_format_table[chroma_format_idc][bit_depth−4>>2]` (line 153)**: CBS parser enforces `chroma_format_idc ∈ [0,4]` and explicitly rejects value 1, leaving 0,2,3,4 as valid first indices (all within the 5-row table). `bit_depth_minus8` is constrained to [2,8] by CBS, giving bit_depth ∈ {10,12,14,16} after the parser's odd-value filter. `(bit_depth−4)>>2` yields {1,2,2,3} — all within the 5-column table. **No OOB access.**

2. **Negative `find_frame_end` return** (−3 when a 4-byte signature spans buffer boundaries): `ff_combine_frame` explicitly handles negative `next` via its overread mechanism (lines 279–288). The memcpy writes into a buffer sized `next + pc->index + AV_INPUT_BUFFER_PADDING_SIZE`, and reads at most `next + AV_INPUT_BUFFER_PADDING_SIZE` bytes from the input (within the mandatory API padding). **Not a bug.**

3. **Division-by-zero**: `frame_width=0` causes division by zero in `cbs_apv_derive_tile_info` → crash/DoS, **not memory corruption**.

4. **Semantic formula bug**: `bit_depth−4>>2` gives the same index (2) for both bit_depth=12 and bit_depth=14, resulting in wrong pixel format for 14-bit streams. **Logic error, not memory safety.**

5. **`dummy_free` / ref-count assertion**: The `opaque == data` assertion holds by construction; `av_assert1(ref_count == 1)` after `ff_cbs_fragment_reset` is a debug-only check with no memory-corruption consequence in release builds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
