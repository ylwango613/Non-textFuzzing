# VULN 002 - copy_width24_msa() OOB Heap Write - SKIPPED

## Vulnerability Summary

- **Function**: `copy_width24_msa()`
- **File**: `libavcodec/mips/hevc_mc_uni_msa.c` (lines 196-217)
- **Type**: Out-of-bounds heap write
- **Root Cause**: The function ignores the `height` parameter and unconditionally writes 32 rows, causing OOB writes when `height < 32`.

## Why SKIPPED

The test binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is compiled for **x86-64**:

```
ELF 64-bit LSB pie executable, x86-64
```

The vulnerable function `copy_width24_msa()` is located in MIPS MSA (MIPS SIMD Architecture) specific code under `libavcodec/mips/`. This code is only compiled when targeting MIPS hardware with MSA support. On an x86-64 build:

1. The MIPS MSA code files are not compiled at all.
2. The symbol `copy_width24_msa` does not appear in the binary (confirmed via `nm`).
3. Even with a crafted HEVC file containing height < 32, the x86-64 binary would use the generic C fallback path, not the MIPS MSA path.

## Triggering on a Real MIPS Target

To trigger this vulnerability, one would need:
1. An FFmpeg binary compiled for MIPS with MSA support (`--enable-mips --enable-msa`)
2. A crafted HEVC file with a picture height < 32 pixels
3. The file should use inter prediction with 24-wide blocks so `copy_width24_msa()` is called

The attack vector would be: `ffmpeg -i crafted_height_lt32.hevc -f null -`
