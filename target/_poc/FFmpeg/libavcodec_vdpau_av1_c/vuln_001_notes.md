# VULN-001: tile_info Heap OOB Write in vdpau_av1_decode_slice — SKIPPED

## Status

**SKIPPED** — VDPAU hardware acceleration is not available in this environment.

## Environment Check Results

```
$ /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -hwaccels 2>&1
Hardware acceleration methods:
(empty — no methods listed)

$ ls /dev/nvidia* 2>/dev/null
/dev/nvidia0
/dev/nvidia1
/dev/nvidiactl
/dev/nvidia-modeset
/dev/nvidia-uvm
/dev/nvidia-uvm-tools
```

NVIDIA GPU devices are physically present (`/dev/nvidia0`, `/dev/nvidia1`), but VDPAU
is not available as a hardware acceleration method. This indicates either:

1. The FFmpeg binary was compiled without VDPAU support (`--disable-vdpau` or missing
   VDPAU development libraries at build time), or
2. The VDPAU runtime libraries (`libvdpau.so`) are not installed/accessible in the
   current environment.

## Why This Cannot Be Triggered

The vulnerable function `vdpau_av1_decode_slice()` in
`libavcodec/vdpau_av1.c` (lines 287–310) is only reached when:

1. FFmpeg is invoked with `-hwaccel vdpau`
2. A working VDPAU implementation is available at runtime
3. The NVIDIA VDPAU driver exposes AV1 decoding capability

Without VDPAU in the hwaccel list, the `-hwaccel vdpau` flag will fail at
initialization before any decode slice function is ever called. The software AV1
decoder (`libaom-av1` / `dav1d`) takes a completely different code path and does
not touch `vdpau_av1_decode_slice()` or the `VdpPictureInfoAV1.tile_info` array.

## Vulnerability Description (for reference)

- **CWE**: CWE-787 (Out-of-bounds Write)
- **Location**: `libavcodec/vdpau_av1.c`, `vdpau_av1_decode_slice()`, lines 287–310
- **Root Cause**: `nb_slices = tile_cols * tile_rows` can reach up to 4096. The loop
  writes `info->tile_info[i*2]` and `info->tile_info[i*2+1]` without bounds checking.
  `VdpPictureInfoAV1.tile_info` is declared as `uint32_t tile_info[256]` (128 tiles max
  × 2 entries per tile). Writing more than 128 tiles causes a heap out-of-bounds write.
- **Trigger**: An AV1 bitstream with `tile_cols=13, tile_rows=10` (130 tiles, product > 128)
  processed via `-hwaccel vdpau` would trigger the overflow.

## What Would Be Required to Test

To verify this vulnerability, the environment would need:
- VDPAU runtime libraries: `libvdpau.so` (package `libvdpau1` on Ubuntu/Debian)
- NVIDIA VDPAU driver: `libvdpau_nvidia.so` (part of the NVIDIA driver installation)
- FFmpeg built with VDPAU support enabled
- A crafted IVF/AV1 file with tile_cols × tile_rows > 128
- Invocation: `ffmpeg -hwaccel vdpau -i crafted.ivf -f null -`
