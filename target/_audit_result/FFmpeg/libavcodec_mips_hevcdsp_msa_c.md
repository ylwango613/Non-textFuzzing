**Complete analysis summary across all 9 batches (lines 1–4400):**

The file contains exclusively MIPS MSA SIMD-optimized HEVC motion-compensation (MC) DSP kernels:
- `hevc_copy_*w_msa` — pel-copy functions
- `hevc_hz_8t_*w_msa` / `hevc_hz_4t_*w_msa` — horizontal 8-tap / 4-tap (qpel/epel)
- `hevc_vt_8t_*w_msa` / `hevc_vt_4t_*w_msa` — vertical filters
- `hevc_hv_8t_*w_msa` / `hevc_hv_4t_*w_msa` — combined H+V filters

No memory allocation (`av_malloc`, `memcpy` with user-controlled sizes), no packet/container parsing, no extradata handling, and no external-input-derived size computations exist anywhere in this file.

All functions operate on pre-allocated HEVC frame buffers that include standard edge padding (right + bottom) to accommodate SIMD over-reads past block boundaries (e.g., `LD_SB` loading 16 bytes for a 4- or 6-pixel-wide block). Block width and height parameters are constrained by the HEVC standard and are validated by the HEVC decoder before these kernels are invoked—no untrusted width/height from the bitstream reaches these functions unchecked. The SIMD over-read patterns (e.g., `LD_SB(src + 24)` in `hevc_hz_8t_32w_msa`, `LD_SB(src + 56)` in `hevc_hz_8t_64w_msa`) are intentional and covered by FFmpeg's frame allocation padding. The hardcoded iteration counts in functions like `hevc_hz_8t_12w_msa` match the single valid HEVC block height (16) for that width.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
