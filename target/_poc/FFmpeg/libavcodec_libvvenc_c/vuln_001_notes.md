# VULN-001 PoC Notes — libavcodec/libvvenc.c integer overflow

## Status: SKIPPED

## Reason

The `libvvenc` encoder is not compiled into the target FFmpeg binary at:

    /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg

Verification command:

    /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -encoders 2>&1 | grep -i vvenc

The command produced no output, confirming that the encoder was not enabled at build time (requires the external `vvenc` library and the `--enable-libvvenc` configure flag).

## Vulnerability Summary (not triggered)

- **File**: `libavcodec/libvvenc.c`
- **Function**: `vvenc_init()`, lines 331–336
- **Root cause**: `avctx->width * avctx->height` performs a signed 32-bit multiply with no cast to `int64_t` or `size_t`. With width=65536 and height=32769 the product overflows INT_MAX, yielding a small (or negative) value that is passed to `vvenc_accessUnit_alloc_payload()`, causing an under-allocated buffer that subsequent `vvenc_encode()` calls write past.
- **Attack vector**: A crafted MKV/MP4 container with attacker-controlled PixelWidth/PixelHeight causes the overflow when `ffmpeg -i evil.mkv -c:v libvvenc out.mp4` triggers `avcodec_open2()` → `vvenc_init()`.

## To reproduce (if libvvenc becomes available)

1. Rebuild FFmpeg with `--enable-libvvenc` and the vvenc library installed.
2. Run `vuln_001_gen.py` (to be created) to craft the MKV container.
3. Run `vuln_001_run.sh` to invoke the ASAN-instrumented binary.
4. Observe heap-buffer-overflow in ASAN output.
