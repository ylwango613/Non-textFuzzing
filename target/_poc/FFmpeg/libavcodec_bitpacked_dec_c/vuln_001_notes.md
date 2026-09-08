# VULN 001 PoC Notes

## Vulnerability Summary

**CWE-125: Out-of-bounds Read** in `bitpacked_decode_uyvy422()`,
file: `libavcodec/bitpacked_dec.c`, lines 40-60.

## Root Cause

`bitpacked_decode_uyvy422` performs a zero-copy "passthrough": it sets
`frame->buf[0]` to reference `avpkt->buf` directly, then calls
`av_image_fill_arrays(frame->data, frame->linesize, avpkt->data, ...)` to
populate `frame->data[0]` with a pointer into the packet buffer.

The return value of `av_image_fill_arrays` is only checked for `< 0`
(API error). **There is no check that `avpkt->size >= width * height * 2`.**

When the packet is undersized, `frame->data[0]` points into a buffer that is
smaller than the frame dimensions imply. Any downstream consumer that reads
`frame->data[0]` using `frame->linesize[0] * frame->height` bytes will perform
a heap out-of-bounds read.

## Trigger Conditions

The vulnerable code path is selected in `bitpacked_init_decoder` when ALL of:
- `avctx->codec_tag == MKTAG('U','Y','V','Y')`
- `avctx->bits_per_coded_sample == 16`
- `avctx->pix_fmt == AV_PIX_FMT_UYVY422`

In AVI, these come from `BITMAPINFOHEADER`:
- `biCompression = 'UYVY'` → sets codec_tag
- `biBitCount = 16` → sets bits_per_coded_sample (FFmpeg then maps to UYVY422)

## PoC Approach

1. `vuln_001_gen.py` generates a valid AVI container with:
   - Dimensions: 64×64 (requires 8192 bytes per UYVY422 frame)
   - Actual `00dc` chunk payload: 16 bytes only
   - `BITMAPINFOHEADER` with `biBitCount=16`, `biCompression='UYVY'`

2. `vuln_001_run.sh` runs ffmpeg with four different output modes to force
   the frame data to be actually consumed:
   - `-f null -` (basic decode)
   - `-vcodec rawvideo -f rawvideo /dev/null` (raw frame copy)
   - `-vf scale=4:4` (scale filter reads all planes)
   - `-pix_fmt rgb24` (pixel format conversion reads full UYVY source)

## Expected Behavior with ASAN

With AddressSanitizer, the OOB heap read should be caught as:
```
ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size N at ...
```

Without ASAN, the bug causes silent corruption / use of uninitialized memory,
which may cause visible artifacts or a crash depending on memory layout.
