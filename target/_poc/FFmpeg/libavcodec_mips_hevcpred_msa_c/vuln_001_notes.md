# VULN 001 - SKIPPED

## Reason: Architecture Mismatch

**Vulnerability**: Stack OOB Read in MIPS MSA HEVC 32x32 Steep Angular Intra Prediction  
**Affected code**: `libavcodec/mips/hevcpred_msa.c` — `hevc_intra_pred_angular_upper_32width_msa()` and `hevc_intra_pred_angular_lower_32width_msa()`

## Why Skipped

The vulnerable code path is MIPS-specific SIMD (MSA — MIPS SIMD Architecture) code. It is only compiled and registered as function pointers when:

1. The target CPU architecture is MIPS, AND
2. The hardware supports the MSA extension (MIPS SIMD Architecture), AND
3. The decoded HEVC bitstream uses 8-bit depth

This environment is **x86_64**:
- `uname -m` returns: `x86_64`
- `file /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` returns: `ELF 64-bit LSB pie executable, x86-64`

On x86_64:
- The MIPS-specific source file `libavcodec/mips/hevcpred_msa.c` is not compiled into the binary at all.
- The MSA function pointers (`hevc_intra_pred_angular_upper_32width_msa`, etc.) are never registered into the codec's function dispatch table.
- No matter how a crafted HEVC bitstream is constructed, the decoder will use the generic C or x86 SIMD intra prediction implementation, never the vulnerable MIPS MSA path.

Therefore, this vulnerability **cannot be triggered** by passing a crafted media file to the ffmpeg command line on this system.
