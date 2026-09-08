# Vulnerability 002 — SKIPPED

## Title
Out-of-Bounds Read in mediacodec_receive — Missing out_info.offset + out_info.size Bounds Check

## Reason for Skip

The vulnerability resides in `libavcodec/mediacodecenc.c`, specifically in the `mediacodec_receive()` function, which uses the Android MediaCodec API via JNI/NDK.

### Encoder availability check

Running the following command on this Linux system returned no output:

```
/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -encoders 2>/dev/null | grep mediacodec
```

No `h264_mediacodec` (or any `*_mediacodec`) encoder is registered, which confirms that the MediaCodec backend is not compiled or available on this Linux host.

### Why triggering is impossible here

1. **Android-only API**: `ff_AMediaCodec_dequeueOutputBuffer()` and the surrounding MediaCodec infrastructure are Android NDK/JNI calls (`android/media/MediaCodec` Java class accessed through JNI). They do not exist on Linux.

2. **Requires hardware/vendor codec**: Even on Android, `h264_mediacodec` depends on a vendor-provided hardware or software codec that exposes the MediaCodec interface. Crafting a media file cannot substitute for this hardware/OS dependency.

3. **Vulnerability is in codec output processing, not demuxing/parsing**: The OOB read occurs after `ff_AMediaCodec_dequeueOutputBuffer()` returns a buffer with a malicious `out_info.offset` or `out_info.size`. This return value comes from the Android MediaCodec runtime, not from parsing the input media file. No crafted input file can force the Android MediaCodec to return an out-of-bounds offset/size from user space on Linux.

4. **No attack surface via ffmpeg CLI on Linux**: The trigger path `ffmpeg -i <crafted_file> -vcodec h264_mediacodec output.mp4` immediately fails on Linux because the encoder is unavailable. There is no code path that reaches `mediacodec_receive()`.

## CWE
CWE-125 (Out-of-Bounds Read)

## Affected Lines
- `libavcodec/mediacodecenc.c` lines 723, 738 (`memcpy(s->extradata, out_buf + out_info.offset, out_info.size)`)
