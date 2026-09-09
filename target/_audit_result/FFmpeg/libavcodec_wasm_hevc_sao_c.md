**Analysis complete.** I've read every function in the file and traced all relevant callers and data structures:

- `wasm_v128_load(sao_offset_val)` loads 16 bytes from `int16_t offset_val[3][5]` (10 bytes per channel). The 6-byte over-read is technically UB, but the swizzle index computation (`edge_idx` → ×2 byte offsets 0,2,4,6,8 and +1 → 1,3,5,7,9) never addresses bytes beyond index 9, so the over-read data never influences any output or write. The memory region is within the same heap struct for all three channels.
- `eo` is decoded as 2 bits (0–3) by `ff_hevc_sao_eo_class_decode`, which is always in bounds for `pos[4][2][2]`.
- `sao_left_class` is always masked `& 31` before indexing `offset_table[32]` — safe.
- The `8x8` variants process 2 rows per loop (`y -= 2`). The caller's `edge_emu_buffer` carries `AV_INPUT_BUFFER_PADDING_SIZE` = 64 bytes of padding, and HEVC CTU heights are always even powers-of-2, so no OOB write occurs.
- `HEVC_MAX_PB_SIZE` (64) matches `MAX_PB_SIZE` (hevc/dsp.h), so the hardcoded `stride_src` is consistent with the buffer allocated by `filter.c`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
