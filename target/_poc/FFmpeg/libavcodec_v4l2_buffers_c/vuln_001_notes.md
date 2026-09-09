# VULN 001 — v4l2_bufref_to_buf unsigned-underflow → OOB write

## Status: SKIPPED

## Reason

This vulnerability is located in `v4l2_bufref_to_buf()` (libavcodec/v4l2_buffers.c, lines 306–309),
which is only reachable through the V4L2 mem2mem (M2M) hardware encoder pipeline:

```
ffmpeg -i crafted.mp4 -c:v v4l2m2m out.mkv
  → avcodec_send_packet()
  → ff_v4l2_context_enqueue_packet()
  → ff_v4l2_buffer_avframe_to_buf()
  → v4l2_buffer_swframe_to_buf()
  → v4l2_bufref_to_buf()   ← vulnerable function
```

### System Check Results

| Check | Result |
|-------|--------|
| `ls /dev/video*` | NO_V4L2_DEVICES (no video devices present) |
| v4l2m2m encoders compiled in ffmpeg | YES (h264_v4l2m2m, hevc_v4l2m2m, vp8_v4l2m2m, etc.) |

### Why Triggering is Impossible Without Hardware

1. **No `/dev/video*` devices exist** on this system. The Linux kernel V4L2 subsystem requires a
   physical or emulated video device node for the M2M codec to open and negotiate buffers.

2. When `ffmpeg -c:v v4l2m2m` is invoked without any `/dev/video*` device, FFmpeg's
   `ff_v4l2_m2m_codec_init()` fails at the `open()` syscall on the device node before any
   buffer allocation or encoding ever occurs. The vulnerable `v4l2_bufref_to_buf()` function
   is never called.

3. The bug is triggered by a **stride-padding mismatch** between the software decoder's output
   frame (`linesize[0]` containing alignment padding, e.g. 4096 bytes/row for a 1920-wide frame)
   and the V4L2 mmap buffer negotiated by the hardware driver for unpadded storage
   (1920 × 1080 × 3/2 = 3,110,400 bytes). This mismatch causes `offset > length` on the
   second plane call, which triggers an unsigned integer underflow (`length - offset` wraps
   to ~4 GB), and `memcpy` with a ~4 GB count past the end of the mmap region.

4. No software-only fallback or emulation layer exists for v4l2m2m on this system that would
   allow this code path to execute.

## What Would Be Needed to Trigger

- A Linux system with a V4L2 M2M-capable hardware encoder (e.g., Raspberry Pi VideoCore IV/VI,
  Rockchip VPU, AllWinner VPU, or an emulated V4L2 device via `vivid` kernel module).
- A crafted input video whose decoder output `linesize[0]` contains stride padding (e.g.,
  width aligned to 4096 bytes) that exceeds the V4L2 driver's mmap buffer total size.
- Command: `ffmpeg -i crafted.mp4 -c:v h264_v4l2m2m out.mkv`

## Vulnerability Summary (for reference)

- **CWE**: CWE-191 (Integer Underflow) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **Impact**: OOB write past mmap region → process crash (DoS) or potential RCE via heap corruption
