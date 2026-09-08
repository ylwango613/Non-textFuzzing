# VULN 002 – Signed Integer Overflow in `height * stride` → Heap OOB Write

## Status: SKIPPED

## Reason

The vulnerability resides exclusively in the Android MediaCodec software-buffer
copy path:

- `ff_mediacodec_sw_buffer_copy_yuv420_planar()` (line 111)
- `ff_mediacodec_sw_buffer_copy_yuv420_semi_planar()` (line 159)
- `ff_mediacodec_sw_buffer_copy_yuv420_packed_semi_planar()` (line 207)

These functions are reachable only through:

```
ff_mediacodec_dec_receive()
  → mediacodec_wrap_sw_video_buffer()
    → ff_mediacodec_sw_buffer_copy_yuv420_*()
```

The `ff_mediacodec_dec_receive` decoder backend is part of the Android
MediaCodec subsystem (`libmediandk` / `libandroid`), which is only present on
Android devices.

## Verification

Running:
```
/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -decoders 2>/dev/null | grep -i mediacodec
```
produces **no output**, confirming that this FFmpeg build contains no
MediaCodec-backed decoders.

## Conclusion

On a Linux host the MediaCodec execution path is never compiled in or linked.
There is no crafted media file that can exercise
`ff_mediacodec_sw_buffer_copy_yuv420_*()` via the `ffmpeg` command-line tool on
this system. The vulnerability cannot be triggered by passing a crafted media
file to the ffmpeg binary on Linux.
