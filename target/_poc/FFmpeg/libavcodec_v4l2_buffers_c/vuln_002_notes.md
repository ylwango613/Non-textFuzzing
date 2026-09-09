# VULN 002 - v4l2_buf_to_bufref OOB Read - SKIPPED

## Vulnerability Summary

- **File**: `libavcodec/v4l2_buffers.c`
- **Function**: `v4l2_buf_to_bufref()`
- **Lines**: 287-288
- **Type**: Out-of-bounds read (OOB read)

## Why Skipped

This vulnerability **cannot be triggered by passing a crafted media file** to the ffmpeg CLI on this system.

### System Check Results

1. **V4L2 devices**: `ls /dev/video*` returns nothing — `NO_V4L2_DEVICES`
2. **V4L2 M2M decoders**: The binary has V4L2 M2M codec wrappers compiled in (h264_v4l2m2m, vp8_v4l2m2m, etc.), but they cannot activate without hardware.

### Why Hardware Is Required

The vulnerable code path is:

```
ffmpeg -i crafted.mp4 -c:v v4l2m2m out.mkv
  -> avcodec_receive_packet()
  -> ff_v4l2_context_dequeue_packet()
  -> ff_v4l2_buffer_buf_to_avpkt()
  -> v4l2_buf_to_bufref()       <-- BUG HERE
```

The function `v4l2_buf_to_bufref()` at lines 287-288 calls `av_buffer_create()` with the full mmap length instead of `length - data_offset`. This allows downstream codec parsers to read `pkt->buf` past the valid mmap region. However, reaching this code requires:

1. A real `/dev/videoN` V4L2 M2M device node that the kernel exposes.
2. `ioctl(fd, VIDIOC_QBUF/DQBUF, ...)` calls that succeed and populate `v4l2_buf->data_offset` with a non-zero value.
3. The mmap'd buffer to be allocated by the kernel driver.

None of these steps can be simulated or spoofed through a crafted input media file alone. The V4L2 subsystem requires kernel-level driver interaction; without `/dev/video*` present, every attempt to open a V4L2 M2M context fails immediately with `ENODEV` before any packet data is processed.

### Conclusion

Triggering the OOB read requires a real V4L2 M2M-capable hardware device (e.g., a Raspberry Pi with the bcm2835-v4l2 driver, or a system with a supported V4L2 M2M encoder chip) plus the appropriate kernel driver loaded. This environment provides neither, so PoC generation is not possible via the allowed methods (CLI-driven crafted media file).
