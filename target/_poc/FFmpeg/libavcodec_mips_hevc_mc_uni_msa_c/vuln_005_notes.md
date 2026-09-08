# VULN 005 - SKIPPED

## Vulnerability
- **Function**: `common_hz_4t_24w_msa()`
- **File**: `libavcodec/mips/hevc_mc_uni_msa.c`, lines 2403-2484
- **Description**: The function ignores the `height` parameter and always writes 32 rows (hardcoded `loop_cnt=8`, 4 rows per iteration), causing an OOB heap write when `height < 32`.

## Why Skipped

This vulnerability is in MIPS MSA (MIPS SIMD Architecture) specific code, located under `libavcodec/mips/`. The code is only compiled when targeting MIPS hardware with MSA support.

**Architecture check results:**
- `file` output: `ELF 64-bit LSB pie executable, x86-64` — the binary is x86_64, not MIPS.
- `nm` search for `common_hz_4t_24w_msa`: symbol **not found** in the binary.

Because the vulnerable function is not compiled into the test binary (`/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg`), there is no way to trigger this vulnerability by passing a crafted media file to this binary. The vulnerability can only be exercised on a MIPS device (or MIPS emulator/cross-compiled binary) with MSA support enabled.

## Trigger Conditions (if MIPS binary were available)

To trigger the OOB write, one would need:
1. An HEVC file with a motion-compensated block using 4-tap horizontal filtering at 24-pixel width.
2. The coded block height set to a value less than 32 (e.g., 4, 8, or 16).
3. The function `common_hz_4t_24w_msa()` would then write 32 rows regardless of the actual height, overwriting heap memory beyond the destination buffer.
