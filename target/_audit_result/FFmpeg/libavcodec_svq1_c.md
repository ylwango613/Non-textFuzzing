I have now completed a thorough multi-pass analysis of all SVQ1 source files:

**Analyzed files:**
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/svq1.c` — shared data table (44 lines, no code)
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/svq1dec.c` — decoder (875 lines, fully read in batches)
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/svq1_cb.h` — codebook arrays
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/svq1_vlc.h` — VLC tables
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/svq1.h` — declarations
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/utils.c` — `avcodec_align_dimensions2`, `ff_set_dimensions`
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/get_buffer.c` — `avcodec_default_get_buffer2`

**Key findings from each analysis pass:**

1. **Chroma frame buffer OOB (initially suspected, ruled out):** `svq1_decode_frame` uses `FFALIGN(s->height/4, 16)` chroma rows, which could exceed the actual allocated buffer. However, `avcodec_align_dimensions2` has an explicit special case for `AV_CODEC_ID_SVQ1 + AV_PIX_FMT_YUV410P` setting `w_align=64, h_align=64`. This guarantees the chroma buffer always has `FFALIGN(height,64)/4 ≥ FFALIGN(floor(height/4),16)` rows — provably sufficient.

2. **Codebook OOB (ruled out):** `entries[j] = ((...&0xF) + 16*j) << (level+1)` gives max index 95·2^(L+1). Combined with per-step `codebook++`, the maximum final access index exactly fits each level's codebook (768, 1536, 3072, 6144 bytes for L=0..3). Levels 4–5 have NULL codebooks but `stages > 0 && level >= 4` returns `AVERROR_INVALIDDATA`, so NULL is never dereferenced.

3. **PMV array OOB (ruled out):** Allocation `(FFALIGN(s->width,16)/8 + 3)` elements; maximum access index `x/8 + 4 = FFALIGN(w,16)/8 + 2 < allocation`. Chroma accesses are even smaller.

4. **`list[63]` OOB in `SVQ1_PROCESS_VECTOR` (ruled out):** The recursive block BFS tree has at most 1+2+4+8+16 = 31 total nodes; max `n` = 31 < 63.

5. **`svq1_parse_string` stack OOB (ruled out):** Buffer declared `[257]`; `out[0]` ≤ 255, writes `out[1..255]` in loop and `out[256]` after — exactly fills [257].

6. **Integer overflow in allocations (ruled out):** All multiplications (e.g., `515 * sizeof(svq1_pmv) = 4120`) are well within `int` range.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
