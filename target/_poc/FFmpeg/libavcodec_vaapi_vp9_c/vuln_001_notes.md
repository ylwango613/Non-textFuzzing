# VULN-001 — vaapi_vp9_start_frame NULL Pointer Dereference — SKIPPED

## Status: SKIPPED

## Reason

The vulnerability in `vaapi_vp9_start_frame()` (libavcodec/vaapi_vp9.c, lines 45–56) requires that FFmpeg be invoked with `-hwaccel vaapi` so that the VAAPI VP9 hardware accelerator is selected. The vulnerable dereference at lines 55–56:

```c
const AVPixFmtDescriptor *pixdesc = av_pix_fmt_desc_get(avctx->sw_pix_fmt);
...
.subsampling_x = pixdesc->log2_chroma_w,
.subsampling_y = pixdesc->log2_chroma_h,
```

is only reachable via `vaapi_vp9_start_frame()`, which is registered as the `.start_frame` callback of the `ff_vp9_vaapi_hwaccel` accelerator.

## Environment Check Results

- `/dev/dri/` exists with render nodes: `renderD128`, `renderD129`, `card0`, `card1`, `card2`
- VAAPI driver libraries present in `/usr/lib/x86_64-linux-gnu/dri/` (e.g., `i965_drv_video.so`, `iHD_drv_video.so`, `radeonsi_drv_video.so`)
- `vainfo` tool not installed
- **Critical finding**: `ffmpeg -hwaccels` reports an **empty list** — the ASAN build binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` was compiled **without any hardware acceleration support**, including VAAPI.

## Conclusion

Because the ffmpeg ASAN binary has no VAAPI support compiled in, passing `-hwaccel vaapi` to it will either fail at initialization or be silently ignored. The `ff_vp9_vaapi_hwaccel` accelerator callbacks are not linked into this binary, so `vaapi_vp9_start_frame()` is never called regardless of the input file content. The vulnerability cannot be triggered by any crafted media file passed to this binary.

A PoC would only be viable with an ffmpeg build compiled with `--enable-vaapi` and a working VAAPI driver/device accessible at runtime.
