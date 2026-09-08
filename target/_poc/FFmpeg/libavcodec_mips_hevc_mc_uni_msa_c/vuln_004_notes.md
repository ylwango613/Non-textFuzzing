# VULN 004 - SKIPPED

## Vulnerability
- **Function**: `hevc_hv_uni_4t_6w_msa()`
- **File**: `libavcodec/mips/hevc_mc_uni_msa.c`, lines 3409-3526
- **Issue**: Ignores the `height` parameter and always writes 8 rows. For `height=4` (chroma 6x4 block from a 12x8 luma PU), it writes 4 extra rows beyond the allocated buffer — an out-of-bounds write.

## Why Skipped

The test binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is an **x86-64 ELF** executable:

```
ELF 64-bit LSB pie executable, x86-64
```

The vulnerable function `hevc_hv_uni_4t_6w_msa` lives in MIPS-specific MSA (MIPS SIMD Architecture) source code under `libavcodec/mips/`. This code is gated by `#ifdef HAVE_MSA` / MIPS build flags and is **not compiled** for x86-64 targets. Consequently:

- `nm` finds no symbol `hevc_hv_uni_4t_6w_msa` in the binary.
- The code path is never reached when running the x86-64 ffmpeg binary regardless of input.
- No crafted media file can trigger this code on an x86-64 host.

## Conditions Required to Reproduce

To reproduce this vulnerability, the ffmpeg binary must be compiled for a **MIPS** target with MSA support enabled (e.g., `mips64el` or `mips32r2` with `-mmsa`). Only then would a crafted HEVC file containing a 12x8 luma PU (producing a 6x4 chroma block) cause `hevc_hv_uni_4t_6w_msa` to be called with `height=4`, triggering the out-of-bounds write.
