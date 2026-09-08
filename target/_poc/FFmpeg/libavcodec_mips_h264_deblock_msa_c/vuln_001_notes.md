# VULN 001 — OOB Read in MIPS MSA H.264 Deblocking Filter

## Status: SKIPPED

## Reason

The vulnerability resides in `libavcodec/mips/h264_deblock_msa.c`, which contains
MIPS MSA (MIPS SIMD Architecture) specific code. The code is compiled and linked only
when FFmpeg is built for a MIPS target with MSA support.

The target binary at:

    /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

is an **ELF 64-bit LSB pie executable, x86-64** (confirmed via `file`). The MIPS MSA
code path (`ff_h264_loop_filter_strength_msa`, `h264_loop_filter_strength_iteration_msa`
macro, and the `LD_SB(ref_t + 52)` OOB read) is never compiled into an x86-64 binary.
The function pointer `h->h264dsp.loop_filter_strength` will point to the generic C
fallback on x86-64, not the MIPS MSA implementation.

Therefore, no crafted H.264 B-frame input can trigger this code path on the current
binary, regardless of macroblock type or bidir prediction mode.

## What would be needed to verify

- A MIPS-architecture build of FFmpeg with MSA support enabled (`--enable-mipsdsp` /
  `--enable-msa` at configure time), or an emulated MIPS environment (e.g., QEMU
  user-mode `qemu-mips`).
- A crafted H.264 B-frame stream with `list_count==2` and non-16x16 macroblock types
  (`edges=4`) to force `h264_loop_filter_strength_iteration_msa` to read
  `ref_t + 52` (16 bytes past the 48-byte `ref_cache` column), triggering the OOB read.
