# VULN 003 - SKIPPED

## Vulnerability
- **Function**: `common_hz_8t_48w_msa()`
- **File**: `libavcodec/mips/hevc_mc_uni_msa.c`, lines 741-825
- **Description**: The function ignores the `height` parameter and always processes 64 rows (hardcoded `loop_cnt=64`), causing an out-of-bounds heap write when `height < 64`.

## Why Skipped

The vulnerability resides in MIPS MSA (MIPS SIMD Architecture) specific code located under `libavcodec/mips/`. This code is only compiled when targeting MIPS hardware with MSA support.

**Architecture check result:**
```
/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg: ELF 64-bit LSB pie executable, x86-64
```

The test binary is compiled for **x86-64**, not MIPS. As a result:
1. The MIPS MSA code path (`common_hz_8t_48w_msa`) is not compiled into the binary.
2. Confirmed via `nm`: the symbol `common_hz_8t_48w_msa` is absent from the binary.
3. There is no way to trigger this code path by passing a crafted media file to the provided ffmpeg binary.

## Triggering on MIPS
To exercise this vulnerability, one would need an FFmpeg binary compiled for MIPS with MSA extensions (e.g., using a MIPS cross-compiler with `-mmsa` or on a MIPS board), then craft an HEVC file that causes the HEVC decoder to invoke `hevc_put_hevc_uni_qpel_h48w` (or a related MC function) with a block height less than 64.
