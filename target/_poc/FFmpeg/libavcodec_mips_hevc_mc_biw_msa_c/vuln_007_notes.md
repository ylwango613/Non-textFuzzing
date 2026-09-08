# VULN 007 — Skip Notes

## Vulnerability Summary

**Function:** `hevc_hv_biwgt_8t_12w_msa()` in `libavcodec/mips/hevc_mc_biw_msa.c`

**Description:** `hevc_hv_biwgt_8t_12w_msa` ignores the `height` parameter and hardcodes 16 rows of processing. When the actual block height is less than 16, the function reads and writes beyond the bounds of the allocated buffers, resulting in an out-of-bounds (OOB) read/write.

## Skip Reason: Architecture Mismatch

This vulnerability is not triggerable on the target system.

The target ffmpeg binary located at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is an **x86-64 ELF binary**. The vulnerable function `hevc_hv_biwgt_8t_12w_msa` is part of the **MIPS MSA (MIPS SIMD Architecture)** optimized code path, which is only compiled and active on MIPS processors that have MSA support.

On x86-64:

- The MIPS-specific DSP init function `ff_hevc_dsp_init_mips()` is never compiled in or called.
- The MSA function pointers (including `hevc_hv_biwgt_8t_12w_msa`) are never registered in the `HEVCDSPContext` function table.
- Instead, x86 SIMD optimizations (SSE2/SSE4/AVX2) are used for HEVC DSP operations.
- No crafted media file input can cause the x86-64 binary to branch into MIPS MSA code.

## Conclusion

There is no viable exploit path for VULN 007 against the x86-64 ffmpeg binary. A proof-of-concept would only be possible when running a MIPS-compiled ffmpeg binary on actual MIPS hardware with MSA support enabled. This PoC is therefore skipped.
