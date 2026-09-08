# VULN 001 - OOB Read via Unchecked `src` Offset in YUV420 SW Copy Functions

## Status: SKIPPED

## Reason

The vulnerability is in the Android MediaCodec path (`ff_mediacodec_dec_receive` →
`mediacodec_wrap_sw_video_buffer` → `ff_mediacodec_sw_buffer_copy_yuv420_*`).

The ffmpeg binary under test is built for **Linux**, and the MediaCodec subsystem is
an Android-only feature. Verification:

```
/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -decoders 2>/dev/null | grep -i mediacodec
(no output)
```

No mediacodec decoders are registered in this binary. The trigger path requires a
MediaCodec-backed decoder to be available and selected at runtime, which is impossible
on a Linux host regardless of the input file.

## Trigger Path (Android only)

```
ffmpeg -i <crafted_video> -f null -
  → avformat_open_input()
  → av_read_frame()
  → avcodec_send_packet()
  → ff_mediacodec_dec_receive()          ← Android MediaCodec API
  → mediacodec_wrap_sw_video_buffer()
  → ff_mediacodec_sw_buffer_copy_yuv420_planar()  ← OOB read here
```

## Conclusion

This vulnerability **cannot** be triggered by passing a crafted media file to the
ffmpeg command line on Linux. A real trigger would require an Android device or
emulator with MediaCodec support built into FFmpeg.
