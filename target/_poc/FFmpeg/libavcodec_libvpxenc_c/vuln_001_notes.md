# VULN 001 — Integer Overflow in realloc_alpha_uv — SKIPPED

## Reason

The vulnerability cannot be triggered by passing a crafted media file to the pre-built FFmpeg binary at:

    /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

**The libvpx-vp9 encoder is not compiled into this binary.**

Running:

    ffmpeg -encoders 2>/dev/null | grep -i vpx

returns no output. The only VP-family encoder present is `vp8_v4l2m2m` (a V4L2 mem2mem hardware wrapper for VP8), not `libvpx-vp9`.

Running:

    ffmpeg -buildconf 2>/dev/null | grep -i vpx

also returns no output, confirming that the build was configured without `--enable-libvpx`.

## Vulnerability Summary

The bug is in `realloc_alpha_uv()` in `libavcodec/libvpxenc.c` (lines 1764–1765). When encoding a YUVA video with >8-bit depth to libvpx-vp9, the expression `stride[VPX_PLANE_U] * height` is computed in signed 32-bit int. At dimensions ≥ 46342×46342 (stride ≈ 46342×2 bytes for 10-bit), the product overflows `INT_MAX`, wraps to a large negative value, and is passed as the `len` argument to `av_memcpy_backptr` → `fill16`, which loops approximately 2^32 times writing far beyond the allocated buffer.

## Why SKIPPED

Without `libvpx` compiled in, the encoder entry point (`vpx_encode`) is unreachable through the public API. No crafted input file or lavfi source can reach `realloc_alpha_uv()`. A PoC requiring a custom build of FFmpeg with `--enable-libvpx` falls outside the scope of "passing a crafted media file to the ffmpeg binary."
