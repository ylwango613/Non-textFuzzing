# VULN 001 — Skip Notes

## Vulnerability Summary

- **ID:** VULN 001
- **Function:** `hevc_biwgt_copy_48w_msa()` in `libavcodec/mips/hevc_mc_biw_msa.c`
- **Description:** `hevc_biwgt_copy_48w_msa` ignores its `height` parameter and hardcodes 64 rows, leading to an out-of-bounds read/write when the actual block height is less than 64.

## Skip Reason

This vulnerability cannot be triggered through the target binary and is therefore skipped without a PoC.

### Architecture Mismatch

The target ffmpeg binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is an **x86-64 ELF binary**. The vulnerable function `hevc_biwgt_copy_48w_msa()` resides in MIPS MSA (MIPS SIMD Architecture) optimized code under `libavcodec/mips/`.

### Code Path Never Reached on x86-64

MIPS MSA DSP functions are registered exclusively via `ff_hevc_dsp_init_mips()`, which is only compiled and called on actual MIPS hardware that reports MSA capability at runtime. On x86-64 builds, the MIPS source files under `libavcodec/mips/` are not compiled into the binary at all, or if present as dead code, the registration function is never invoked.

On x86-64, the HEVC DSP function table is populated by the x86-specific initialization path (SSE/AVX optimizations), which points to entirely different implementations. There is no code path by which `hevc_biwgt_copy_48w_msa` can be called on an x86-64 system.

### Conclusion

No crafted media file — regardless of its content, codec parameters, or dimensions — can cause the x86-64 `ffmpeg` binary to execute `hevc_biwgt_copy_48w_msa()`. The vulnerability is real but not exploitable on the target platform.
