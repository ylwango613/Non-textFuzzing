After completing a thorough multi-pass analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/h264pred.c` and its included template file `h264pred_template.c`, plus the header and all relevant call sites, here is my assessment:

**Pass 1 (h264pred.c lines 1–604):** The file contains static intra-prediction functions for 4×4, 8×8, and 16×16 blocks for H.264, VP8, SVQ3, and RV40. No `av_malloc`/`av_realloc`, no bitstream-controlled sizes, no dynamic allocations. All writes are into caller-provided frame-buffer pointers with fixed-size, constant strides.

**Pass 2 (h264pred_template.c lines 1–600):** Same pure-arithmetic prediction functions templated over BIT_DEPTH. `CLIP`, `PIXEL_SPLAT_X4`, `AV_WN4PA` macros bound all writes to pixel range. No OOB concern.

**Pass 3 (h264pred_template.c lines 600–1330):** Examined `pred8x8l_vertical_filter_add` / `pred8x8l_horizontal_filter_add`. These cast `int16_t *_block` to `dctcoef *` (= `int32_t *` for BIT_DEPTH > 8), accessing `block[0..63]` and then `memset(_block, 0, sizeof(dctcoef)*64)` = 256 bytes. Verified against the call site (`sl->mb[16*48*2]` = 3072 bytes): worst-case access at `p=2, i=12` clears bytes 2816–3071, landing exactly at the buffer boundary — no overflow.

**Pass 4 (pred16x16/pred8x8 add functions + call sites):** `pred16x16_vertical_add` offsets `block + i*16*sizeof(pixel)` (i up to 15, pixel=2 for high depth → offset 480), then `pred4x4_vertical_add` accesses `block[15]` → max byte offset 1024×2 + 480×2 + 60 = 3068 (within 3072). Tight but correct.

**Pass 5 (ff_crop_tab bounds for VP8 TM modes):** `ff_crop_tab[256 + 2×1024]` = 2304 elements. Maximum index in TM prediction = `MAX_NEG_CROP + 255 + 255 = 1534` < 2303. Safe.

**Pass 6 (function pointer array bounds):** `pred4x4[15]`, `pred8x8l[12]`, `pred8x8[11]`, `pred16x16[9]`. Mode values come from bitstream validation (`ff_h264_check_intra4x4_pred_mode`, `ff_h264_check_intra_pred_mode`) which bounds them to 0–8 (4×4), 0–3 (16×16), etc. No OOB function-pointer dereference.

The file is a collection of pure arithmetic leaf-node prediction functions that write into pre-allocated, decoder-validated frame buffers. There are no `av_malloc` calls, no bitstream-controlled sizes, no unchecked multiplications before buffer writes, and no integer-overflow-to-underallocation paths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
