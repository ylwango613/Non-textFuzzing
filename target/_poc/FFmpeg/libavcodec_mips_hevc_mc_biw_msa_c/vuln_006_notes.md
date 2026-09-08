# VULN 006 — Skip Notes

## Vulnerability Summary

**Function:** `hevc_vt_biwgt_8t_12w_msa()` in `libavcodec/mips/hevc_mc_biw_msa.c`

**Issue:** The function ignores its `height` parameter and hardcodes 16 rows of processing. When called with a height smaller than 16, the function reads and writes beyond the bounds of the allocated buffers, resulting in an out-of-bounds (OOB) read/write.

## Why This Is Skipped

This vulnerability exists exclusively in MIPS MSA (MIPS SIMD Architecture) optimized code. The target binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is an **x86-64 ELF binary**, not a MIPS binary.

The MIPS MSA dispatch path is gated behind `ff_hevc_dsp_init_mips()`, which is only called at runtime on actual MIPS hardware that advertises MSA support in its CPU feature flags. On x86-64:

- The CPU feature detection never activates any MIPS code path.
- The x86 SIMD optimizations (SSE/AVX via `ff_hevc_dsp_init_x86()`) are registered instead.
- The vulnerable function `hevc_vt_biwgt_8t_12w_msa` is never linked into the function dispatch table and is therefore dead code from the perspective of this binary.

No crafted input file — regardless of codec parameters, resolution, or bitstream content — can cause the x86-64 `ffmpeg` binary to execute `hevc_vt_biwgt_8t_12w_msa`. The vulnerability is architecturally unreachable on the test platform.

## Conclusion

A proof-of-concept exploit is not possible against the provided x86-64 binary. This finding would only be exploitable on a MIPS device with MSA support running a MIPS build of FFmpeg. The vulnerability is **skipped** for this target environment.
