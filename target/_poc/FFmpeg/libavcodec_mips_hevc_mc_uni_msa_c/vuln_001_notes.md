# VULN 001 - copy_width12_msa() OOB Heap Write - SKIPPED

## Vulnerability

- **Function**: `copy_width12_msa()`
- **File**: `libavcodec/mips/hevc_mc_uni_msa.c`, lines 146-158
- **Description**: The function ignores the `height` parameter and always writes 16 rows using MIPS MSA (MIPS SIMD Architecture) vector instructions. When called with `height < 16`, this causes an out-of-bounds heap write past the end of the destination buffer.

## Why SKIPPED

The vulnerability resides in MIPS MSA-specific optimized code under `libavcodec/mips/`. This code is only compiled and linked when building for a MIPS target with MSA support.

The test binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is:
- Architecture: **x86-64** (ELF 64-bit LSB pie executable, x86-64)
- The symbol `copy_width12_msa` is **not present** in the binary (confirmed via `nm` grep)

Because the vulnerable function is not compiled into the x86-64 binary, it is impossible to trigger this vulnerability by passing a crafted media file to the provided ffmpeg binary. The MIPS-specific dispatch path (`ff_hevc_put_hevc_uni_*_msa`) would only be selected at runtime on actual MIPS hardware with MSA capability flags set.

## Triggering Conditions (on MIPS hardware)

To trigger the vulnerability on an actual MIPS MSA build:
1. Build FFmpeg for MIPS with MSA support (`--enable-msa`)
2. Create a crafted HEVC bitstream that forces a motion compensation call with a block width of 12 pixels and a height less than 16 (e.g., height=8 or height=4)
3. The HEVC decoder would call `copy_width12_msa()` via the MSA-optimized motion compensation table
4. The function would write 16 rows instead of the requested height, overflowing the destination allocation

## Conclusion

PoC generation is not applicable for the x86-64 binary. This vulnerability would require a MIPS MSA build of FFmpeg and appropriate MIPS hardware (or emulator such as QEMU-MIPS with MSA support) to reproduce.
