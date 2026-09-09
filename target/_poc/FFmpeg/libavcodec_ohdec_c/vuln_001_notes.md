# VULN 001 — OOB Read via TOCTOU Race on Format Fields in oh_decode_wrap_sw_buffer

## Status: SKIPPED

## Reason

This vulnerability cannot be triggered by passing a crafted media file to ffmpeg on the command line for the following reasons:

### 1. Decoder Not Available in Standard Linux FFmpeg Builds

The `h264_ohcodec` (and all `*_ohcodec` variants) decoder is part of OpenHarmony OS-specific hardware codec infrastructure (`libavcodec/ohdec.c`). It is only compiled and functional on OpenHarmony OS devices that expose the hardware codec HAL (Hardware Abstraction Layer).

Verification:
```
$ /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -codecs 2>&1 | grep -i ohcodec
(no output)

$ /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -decoders 2>&1 | grep -i oh
(no ohcodec entries found; only unrelated matches containing "oh" substring)
```

The binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` was built on Linux and does not include OpenHarmony hardware codec support.

### 2. Bug is a Race Condition (CWE-362) Requiring Concurrent Thread Timing

Even if the codec were available, the vulnerability in `oh_decode_wrap_sw_buffer()` (lines 489-533 in `libavcodec/ohdec.c`) is a TOCTOU (Time-of-Check-Time-of-Use) race condition between:
- `oh_decode_on_stream_changed()` — which updates format fields (width, height, pixel format) in the decoder context
- `oh_decode_wrap_sw_buffer()` — which reads those same fields to set up a software buffer

A race requires two concurrent threads operating with specific interleaving. There is no way to craft a media file that reliably triggers the precise thread interleaving needed to expose the OOB read. The condition cannot be deterministically triggered by file content alone.

### 3. Platform and Hardware Requirements

The OpenHarmony hardware codec HAL that `ohdec.c` interfaces with (`OH_AVCodec`, `OH_AVBuffer`, etc.) is only present on OpenHarmony OS. Running the trigger command `ffmpeg -c:v h264_ohcodec -i crafted.h264 -f null -` on a standard Linux system would immediately fail with "Decoder h264_ohcodec not found" before any file parsing occurs.

## Conclusion

This vulnerability is not exploitable via a crafted file on a standard Linux system. A PoC would require:
1. An OpenHarmony OS device or emulator with hardware codec support
2. A custom multi-threaded harness to race `oh_decode_on_stream_changed` and `oh_decode_wrap_sw_buffer`

Both requirements violate the hard rules of this PoC exercise (no custom C/C++ harness, only file-based trigger). Therefore, this vulnerability is **SKIPPED**.
