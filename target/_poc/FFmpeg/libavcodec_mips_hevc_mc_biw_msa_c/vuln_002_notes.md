# VULN 002 — Skip Notes

## Vulnerability Summary

- **ID:** VULN 002
- **Function:** `hevc_hz_biwgt_8t_48w_msa()` in `libavcodec/mips/hevc_mc_biw_msa.c`
- **Description:** `hevc_hz_biwgt_8t_48w_msa` ignores the `height` parameter and hardcodes 64 rows, leading to an out-of-bounds read/write when the actual block height is less than 64.

## Reason for Skip

This vulnerability resides in MIPS MSA (MIPS SIMD Architecture) optimized code. The target ffmpeg binary located at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is an **x86-64 ELF binary**, not a MIPS binary.

The MIPS MSA dispatch path is gated behind `ff_hevc_dsp_init_mips()`, which is only invoked at runtime on actual MIPS hardware that reports MSA support via CPU feature detection. On x86-64 hosts, this initialization function is never called; instead, the x86 SIMD optimizations (SSE/AVX) are registered for HEVC DSP operations.

As a result, `hevc_hz_biwgt_8t_48w_msa` is never reachable through the x86-64 ffmpeg binary regardless of what crafted media file is supplied as input. There is no viable code path from the x86-64 binary's HEVC decoder to this MIPS-specific function, making it impossible to trigger the OOB read/write condition described in this vulnerability on the test target.

## Conclusion

No PoC can be constructed for this vulnerability against the x86-64 build. The finding is architecture-specific and would only be exploitable on a MIPS device with MSA support running a MIPS build of FFmpeg.
