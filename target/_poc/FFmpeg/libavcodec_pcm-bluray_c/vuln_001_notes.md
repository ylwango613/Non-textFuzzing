# VULN 001 — Skipped

## Vulnerability
Title: Heap Buffer Overflow in Big-Endian S16 pcm_bluray Decode via Non-Aligned Packet Size
Function: pcm_bluray_decode_frame()
Source: libavcodec/pcm-bluray.c, lines 148-175

## Why Skipped

The vulnerable code path is guarded by the `#if HAVE_BIGENDIAN` preprocessor macro.
This branch is only compiled on big-endian architectures (PowerPC, MIPS BE, SPARC).

The ASAN-instrumented FFmpeg binary provided is:

- Architecture: x86-64 (ELF 64-bit LSB pie executable)
- Endianness: little-endian (LSB)
- Build config: `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/config.h` defines `HAVE_BIGENDIAN 0`

Because `HAVE_BIGENDIAN` is 0, the vulnerable byteswap loop inside `pcm_bluray_decode_frame()` is
not compiled into the binary at all. Passing any crafted Blu-ray PCM file to this ffmpeg binary
cannot reach the vulnerable code path, regardless of the file contents.

## Trigger Condition
To reproduce this vulnerability a big-endian build of FFmpeg (e.g. on a PowerPC or MIPS BE host,
or via cross-compilation with `--target-os` and the appropriate `--arch` flag) would be required,
together with a .m2ts file whose PCM audio packet size is not a multiple of the sample frame size
(buf_size % sample_size != 0 after the size is adjusted), causing the byteswap loop to read/write
past the allocated destination buffer.

## Conclusion
漏洞无法通过向 ffmpeg 命令行传递一个畸形媒体文件来触发 — the vulnerability cannot be triggered by
passing a crafted media file to this (little-endian x86-64) ffmpeg binary.
