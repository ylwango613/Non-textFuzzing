Having read all 2160 lines of `snowenc.c` in four batches and chased down the key supporting headers and support code, here is my complete analysis before the final verdict.

**Batch 1 (lines 1–500) findings:**
- `encode_init()` line 241: `av_calloc(avctx->width + 64, …)` – width is int; no overflow possible at realistic dimensions.
- `encode_init()` line 293: `av_calloc(avctx->width + 128, 2*(2*MB_SIZE+HTAPS_MAX-1))` – same reasoning.
- `encode_init()` line 298: `int size = s->b_width * s->b_height << 2*s->block_max_depth;` – b_width/b_height at most ~2048 for ≤32 K-pixel video; product stays within int32.
- `p_buffer[1024]` / `i_buffer[1024]` in `encode_q_branch()`: inherited `pc.bytestream_end` from heap coder; `renorm_encoder` writes without a bounds check. However, the total symbols written per block (≤3 put_symbol calls at MV magnitudes bounded by MAX_MV=4096) produces at most ~100–150 bytes of range-coded output per block invocation – comfortably inside 1024.

**Batch 2 (lines 500–1000) findings:**
- State array accesses (`p_state[128 + 1024 + 32*ref_context]` etc.): `ref_context ≤ 6`, `mx_context ≤ 16`, max offset = 1375 < `sizeof(block_state)` = 4224. All within bounds.
- No OOB identified in `encode_q_branch2`, `get_dc`, `get_block_rd`, `get_4block_rd`, or `encode_subband_c0run`.

**Batch 3 (lines 1000–1500) findings:**
- `run_buffer` sized at `((width+1)/2)*((height+1)/2)+1`; largest subband at finest DWT level has exactly `(width+1)/2 × (height+1)/2` elements; `run_index` reaches at most that value + 1, fitting precisely. No OOB.
- `quantize`/`dequantize`/`decorrelate`/`correlate` – all loop over `b->width × b->height` with no unbounded indexing.

**Batch 4 (lines 1500–2160) findings:**
- `encode_frame()` line 1784: `s->b_width*s->b_height*MB_SIZE*MB_SIZE*3 + FF_INPUT_BUFFER_MIN_SIZE` is computed in int32. For b_width=b_height=2048 (32 K-pixel video) the product is `~3.2 × 10⁹` → overflows to `-1,073,741,824`. `ff_alloc_packet(…, int64_t size)` receives this negative value and immediately returns `AVERROR(EINVAL)` (confirmed in encode.c line 64). No memory corruption.
- `width * height` in `ff_snow_common_init` line 519: overflows to a small positive value only when `width*height > 2^31`. With AV1's maximum dimension of 65536 per side: `65536² = 2^32`, which as int32 = 0 → `av_calloc(0,…)` → NULL → ENOMEM caught. Values exceeding 65536 per side are outside any supported codec's limits. No practical exploit path.
- `ff_obmc_tab[block_max_depth + chroma_h_shift]`: max index = 1+2 = 3 for YUV410P; array has 4 entries. Within bounds.
- `calculate_visual_weight`, `ratecontrol_1pass`, `encode_header`, `update_last_header_values`: no unbounded memory access.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
