# VULN 001 – VDPAU HEVC Tile Array Heap OOB Write – Skip Notes

## Status: SKIPPED

## Reason

The vulnerability requires FFmpeg to be invoked with `-hwaccel vdpau`, which in turn requires:

1. **VDPAU support compiled into FFmpeg** – the `vdpau_hevc_start_frame()` code path is only reachable when the VDPAU hardware-accelerated HEVC decoder is linked and enabled at runtime.
2. **An NVIDIA GPU with a functional VDPAU driver stack**.

### Findings on this system

| Check | Result |
|---|---|
| NVIDIA GPU present | YES – two NVIDIA devices detected via `lspci` (device 26b9), driver 575.57.08 |
| VDPAU library installed | YES – `/usr/lib/x86_64-linux-gnu/libvdpau.so.1.0.0` present |
| VDPAU listed in `ffmpeg -hwaccels` | **NO** – the "Hardware acceleration methods:" section is empty |
| FFmpeg build flags | Built with `--disable-optimizations --disable-stripping`, **no `--enable-vdpau`** |

The target binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` reports an empty list of hardware acceleration methods, confirming VDPAU was not compiled in. Passing `-hwaccel vdpau` to this binary will produce an error such as `"vdpau requested but not supported"` and the code path leading to `vdpau_hevc_start_frame()` will never execute, regardless of what is in the crafted HEVC file.

## What would be required to trigger the bug

To reproduce this vulnerability one would need:

1. A rebuild of FFmpeg with `--enable-vdpau` (requires `libvdpau-dev` headers and linker support).
2. An NVIDIA GPU accessible to the process (present on this host, so this condition is met).
3. A correctly configured Xorg / offscreen VDPAU context (the VDPAU API requires a display connection even for decode-only use).
4. A crafted HEVC stream with `tiles_enabled_flag=1` and `num_tile_columns_minus1 >= 20` in the PPS, so that the loop at lines 162-170 of `libavcodec/vdpau_hevc.c` writes beyond the fixed-size `VdpPictureInfoHEVC.column_width_minus1[20]` / `row_height_minus1[22]` arrays.

Because condition 1 is not met for the provided binary, PoC files (`vuln_001_gen.py`, `vuln_001_run.sh`) were not generated.
