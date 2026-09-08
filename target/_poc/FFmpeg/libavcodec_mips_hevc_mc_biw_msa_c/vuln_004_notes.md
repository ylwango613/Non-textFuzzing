# VULN 004 — Skip Notes

## Vulnerability Summary

- **ID:** VULN 004
- **Function:** `hevc_hz_biwgt_8t_24w_msa()` in `libavcodec/mips/hevc_mc_biw_msa.c`
- **Description:** `hevc_hz_biwgt_8t_24w_msa` ignores the `height` parameter and hardcodes 32 rows, causing an out-of-bounds read/write when the actual height is less than 32.

## Reason for Skip

This vulnerability exists in MIPS MSA (MIPS SIMD Architecture) optimized code. The target binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is an x86-64 ELF binary, not a MIPS binary.

The MIPS MSA DSP functions — including `hevc_hz_biwgt_8t_24w_msa` — are only registered at runtime through `ff_hevc_dsp_init_mips()`, which is called only when the binary is executing on actual MIPS hardware with MSA capability detected. On x86-64, this initialization path is never taken. Instead, the HEVC DSP function table is populated with x86 SIMD implementations (SSE/AVX) via the corresponding x86 initialization routines.

As a result, there is no mechanism by which a crafted media file can cause the x86-64 ffmpeg binary to call `hevc_hz_biwgt_8t_24w_msa`. The vulnerable code is compiled into the binary only for MIPS targets (or excluded entirely from the x86-64 build), and no amount of input crafting can redirect execution to a MIPS-specific code path on an x86-64 host.

## Conclusion

PoC development is not feasible for this target environment. The vulnerability is architecture-specific (MIPS MSA) and cannot be triggered on the x86-64 test binary.
