# VULN 005 — Skip Notes

## Vulnerability Summary

- **ID:** VULN 005
- **Function:** `hevc_hz_biwgt_8t_12w_msa()` in `libavcodec/mips/hevc_mc_biw_msa.c`
- **Description:** `hevc_hz_biwgt_8t_12w_msa` ignores the `height` parameter and hardcodes 16 rows, leading to an out-of-bounds read/write when the actual block height is less than 16.

## Reason for Skip

This vulnerability resides in MIPS MSA (MIPS SIMD Architecture) optimized code. The target ffmpeg binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is an x86-64 ELF binary, not a MIPS binary.

The MIPS MSA dispatch functions (including `hevc_hz_biwgt_8t_12w_msa`) are only registered through `ff_hevc_dsp_init_mips()`, which is called conditionally on actual MIPS hardware that reports MSA capability at runtime. On x86-64 systems, this initialization path is never taken — the DSP function table is instead populated with x86 SIMD implementations (SSE/AVX).

As a result, there is no way to reach `hevc_hz_biwgt_8t_12w_msa` through the x86-64 ffmpeg binary regardless of what crafted media file is supplied. A PoC cannot be demonstrated on this target platform.

## Trigger Condition (Theoretical)

To trigger this bug, all of the following would be required:

1. An actual MIPS processor with MSA support.
2. An ffmpeg binary compiled for MIPS with MSA enabled.
3. A crafted HEVC bitstream that routes bi-weighted prediction through a 12-pixel-wide block with a height smaller than 16.

None of these conditions are satisfiable with the current x86-64 target binary.

## Status

**SKIPPED** — architecture mismatch; vulnerable code path is unreachable on x86-64.
