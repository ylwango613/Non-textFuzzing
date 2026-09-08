# VULN 001 — Null Pointer Dereference in ff_dxva2_mpeg2_fill_slice

## Status: SKIPPED

## Reason

This vulnerability **cannot be triggered on this system**.

### Platform check

- Current OS: Linux (confirmed via `uname -s`)
- Available hardware accelerators: none (confirmed via `ffmpeg -hwaccels`)

### Why it cannot be triggered

DXVA2 (DirectX Video Acceleration 2) is a **Windows-only API** provided by Microsoft as part of the DirectX framework. It is not available on Linux or macOS. The vulnerability in `ff_dxva2_mpeg2_fill_slice()` (libavcodec/dxva2_mpeg2.c, lines 146–148) is only reachable through the following call chain:

```
ffmpeg -hwaccel dxva2 ...
  → mpeg_decode_slice()
    → dxva2_mpeg2_decode_slice()
      → ff_dxva2_mpeg2_fill_slice()   ← vulnerable function
```

or equivalently with `-hwaccel d3d11va` (Direct3D 11 Video Acceleration, also Windows-only).

The FFmpeg build under test was compiled on Ubuntu Linux (gcc 13, Ubuntu 24.04) and does not include DXVA2 or D3D11VA support. Running `ffmpeg -hwaccels` lists no hardware acceleration methods, confirming neither `dxva2` nor `d3d11va` is compiled in or available.

### Vulnerability summary (for reference)

- **CWE**: CWE-476 (NULL Pointer Dereference)
- **Trigger condition**: When `size < 4` is passed to `ff_dxva2_mpeg2_fill_slice()`, the unsigned subtraction `size - 4` wraps around to `UINT_MAX`. This value is passed to `init_get_bits()`, which sets the internal buffer pointer `s->buffer` to NULL. A subsequent call to `get_bits()` then dereferences that NULL pointer, causing a crash.
- **Attack vector**: A crafted MPEG-2 media file with a slice whose payload is fewer than 4 bytes, processed with `-hwaccel dxva2` or `-hwaccel d3d11va` on a Windows system.

### To reproduce (Windows only)

On a Windows system with a DXVA2-capable GPU and an FFmpeg build that includes DXVA2 support:

```
ffmpeg -i crafted.mpg -hwaccel dxva2 -f null -
```

where `crafted.mpg` contains an MPEG-2 video stream with at least one slice whose data payload is fewer than 4 bytes.
