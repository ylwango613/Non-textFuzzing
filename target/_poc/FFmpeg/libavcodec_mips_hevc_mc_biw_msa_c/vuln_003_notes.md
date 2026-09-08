# VULN 003 — Skip Notes

## Vulnerability Summary

**Function:** `hevc_biwgt_copy_24w_msa()` in `libavcodec/mips/hevc_mc_biw_msa.c`

**Description:** `hevc_biwgt_copy_24w_msa` ignores the `height` parameter and instead hardcodes 32 rows of processing. When called with a `height` value less than 32, the function reads and writes beyond the bounds of the allocated source and destination buffers, resulting in an out-of-bounds (OOB) read/write.

## Why This Is Skipped

This vulnerability exists in MIPS MSA (MIPS SIMD Architecture) optimized code. The PoC cannot be demonstrated against the target binary for the following reasons:

1. **Target binary architecture mismatch.** The ffmpeg binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is an x86-64 ELF binary. The vulnerable function resides in MIPS-specific SIMD code that is only compiled and linked when building for a MIPS target.

2. **Platform-gated registration.** The MIPS MSA DSP functions are registered exclusively through `ff_hevc_dsp_init_mips()`, which is only called on actual MIPS hardware that advertises MSA support at runtime. On x86-64, this initialization path is never entered.

3. **x86 SIMD fallback.** On x86-64 platforms, FFmpeg uses its own set of SIMD optimizations (SSE2/SSE4/AVX2) for HEVC bi-weighted prediction. The MIPS MSA function pointer is never installed into the `HEVCDSPContext` dispatch table, so no crafted media input can route execution to `hevc_biwgt_copy_24w_msa`.

4. **No software fallback exposure.** The bug is not present in the portable C reference implementation; it is isolated to the MIPS MSA variant. The x86-64 build is therefore not affected regardless of input.

## Conclusion

Because the vulnerable code path is architecturally unreachable from the x86-64 target binary, no proof-of-concept exploit can be constructed for this environment. A PoC would only be feasible on a MIPS device with MSA support running an FFmpeg binary compiled for that platform.
