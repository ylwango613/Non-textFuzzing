I have now thoroughly read and analyzed the complete `apv_decode.c` file (631 lines) in multiple passes, traced into `apv_decode.h`, `apv.h`, `cbs_apv.h`, `cbs_apv.c`, and `cbs_apv_syntax_template.c`.

**Summary of analysis per function group:**

**Batch 1 (lines 1–328): `apv_decode_block`, `apv_decode_tile_component`**
- `comp_index = job % nb_components` safely indexes `tile_data[4]`, `tile_qp[4]`, `q_matrix[4][8][8]` — all within `APV_MAX_NUM_COMP = 4`.
- `tile_index = job / nb_components` safely indexes `input->tile[APV_MAX_TILE_COUNT=400]` since CBS guarantees `num_tiles ≤ 400`.
- `block_start = data[comp_index] + frame_y * pitch + 2 * frame_x` stays within the allocated frame buffer: `frame_x` and `frame_y` are bounded by coded dimensions.
- `tile_data_size[comp_index]` cast to int in `init_get_bits8`; if overflowed the function returns error (size ≤ 0 path).

**Batch 2 (lines 330–440): `apv_derive_tile_info`, `apv_decode`**
- `col_starts[APV_MAX_TILE_COLS+1=21]` and `row_starts[APV_MAX_TILE_ROWS+1=21]` are `uint16_t`. For frame_width > 65535, stored values truncate — but when `col_starts[i+1] < col_starts[i]` due to wrap, `tile_width` becomes negative, preventing any loop iteration and blocking OOB writes.
- CBS `av_assert0(tile_cols ≤ 20 && tile_rows ≤ 20)` (always enabled in production) ensures the loop in `apv_derive_tile_info` never writes beyond index 20.
- `apv_format_table[chroma_format_idc][…]` indexing: CBS validates `chroma_format_idc ∈ {0,2,3,4}` (rejects 1), so index 0–4 into a [5][4] table is safe; `bit_depth_minus8 ∈ [2,8]` → second index ∈ [0,3], safe.

**Batch 3 (lines 441–631): `apv_decode_metadata`, `apv_receive_frame_internal`, `apv_receive_frame`**
- `metadata_user_defined`: `data_size = payload_size - 16` can underflow to near-SIZE_MAX if `payload_size < 16`; `av_buffer_alloc` fails → NULL check returns ENOMEM. No heap corruption.
- `metadata_itu_t_t35`: `read_size = payload_size - 1` + potential `--read_size` underflow → same: allocation fails gracefully.
- CBS `tile_size_remaining = tile_size(≥10) - tile_header_size(≤25)` can underflow for 4-component streams; `tile_data_size[c]` limited by `get_bits_left(rw) < 8LL * comp_size` check before any pointer use. No memory corruption.

**Conclusion:** All attack-reachable code paths have sufficient bounds checks (CBS validation, bit-count guards, allocation failure checks) to prevent memory corruption. No externally triggerable memory safety vulnerabilities identified.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
