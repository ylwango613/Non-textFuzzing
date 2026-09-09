# PoC Notes – vuln_001: Integer Overflow → OOB Read in y216_decode_frame()

## Vulnerability Summary

- **File**: `libavcodec/targa_y216dec.c`
- **Function**: `y216_decode_frame()`
- **Lines**: 39–66
- **CWEs**: CWE-190 (Integer Overflow) → CWE-125 (Out-of-Bounds Read)

## Root Cause

Line 42 of `targa_y216dec.c`:

```c
int aligned_width = FFALIGN(avctx->width, 4);          // line 39 — signed int
if (avpkt->size < 4 * avctx->height * aligned_width) { // line 42
```

All operands are signed 32-bit integers.  When `width = height = 23171`:

```
aligned_width = FFALIGN(23171, 4) = 23172
4 * 23171 * 23172 = 2,147,673,648  (> INT_MAX = 2,147,483,647)
```

The product wraps to a large **negative** value (signed overflow is UB in C, but
in practice wraps on x86/x64 with two's-complement).  Any non-negative
`avpkt->size` is then "greater than" a negative bound, so the guard is **always
false** and execution falls through unconditionally into the inner loop.

The loop at lines 54–66 then reads:

```c
src[4 * j]  …  src[4 * j + 3]   // for j up to (width/2 - 1)
```

across `height` rows with a stride of `aligned_width * 2` uint16 elements.
With our 1024-byte payload, the very first access beyond byte 1024 is an
**out-of-bounds read** on the heap.

## Trigger Path

```
ffmpeg -i vuln_001_input.avi -f null -
  └─ avformat_open_input()          — opens AVI, reads stream headers
       └─ demuxer sets avctx->width=23171, avctx->height=23171
            └─ avcodec_send_packet() / avcodec_receive_frame()
                 └─ y216_decode_frame()
                      └─ integer overflow on line 42  →  guard bypassed
                           └─ OOB read in inner loop (lines 55-59)
```

## AVI Container

The crafted file contains:
- **RIFF/AVI** container with a single video stream.
- **Codec fourcc**: `Y216` — confirmed in `libavformat/isom_tags.c`:
  `{ AV_CODEC_ID_TARGA_Y216, MKTAG('Y', '2', '1', '6') }`.
- **Width = Height = 23171** — chosen so that `4 * height * aligned_width`
  overflows a signed 32-bit integer.
- **Video frame payload**: 1024 bytes of zeros — intentionally far smaller than
  what the decoder expects (`4 * 23171 * 23172 ≈ 2.15 GB`).

## Expected Behavior

- Without sanitizers: likely a segfault / SIGSEGV when the out-of-bounds read
  crosses an unmapped page.
- With AddressSanitizer (ASAN): `heap-buffer-overflow` report pointing into
  `y216_decode_frame` at the `src[4*j]` access.
- FFmpeg may also emit "Insufficient input data." if the overflow happens to
  produce a positive result in a different build, but on typical x86-64 the
  product wraps negative and the message is suppressed.

## Why the OOB Read Is Blocked at the CLI Level

The standard `ffmpeg` CLI cannot trigger the OOB read in this FFmpeg build due to
a defense-in-depth check in `avcodec_open2` (`libavcodec/avcodec.c`, lines 241-246):

```c
if ((avctx->coded_width || avctx->width || ...)
    && (av_image_check_size2(avctx->width, avctx->height, ..., AV_PIX_FMT_NONE, ...) < 0))
{
    av_log(avctx, AV_LOG_WARNING, "Ignoring invalid width/height values\n");
    ff_set_dimensions(avctx, 0, 0);   // resets to 0
}
```

`av_image_check_size2` with AV_PIX_FMT_NONE uses a conservative 8-bits/pixel stride
estimate. For 23171×23171: stride = 8×23171+1024 = 186,392 bytes; stride×(h+128) ≈
4.35 billion > INT_MAX → invalid. avcodec_open2 resets width/height to 0 before
calling `y216_decode_init`. All subsequent calls to `y216_decode_frame` therefore
have avctx->width=0/height=0, the product at line 42 is 0, no overflow occurs, and
`ff_get_buffer` immediately rejects the 0×0 dimensions. The loop (lines 54-66) is
never reached.

This is structurally unavoidable: any (w,h) that causes `4*h*aligned_width > INT_MAX`
also causes `stride*(h+128) >= INT_MAX`, so the two checks are mutually exclusive.
The vulnerability is reachable only via direct library use (bypassing or reimplementing
avcodec_open2's dimension validation).

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Python script that writes `vuln_001_input.avi` |
| `vuln_001_run.sh` | Shell script that runs gen + ffmpeg; collects output/ASAN logs |
| `vuln_001_input.avi` | Generated crafted AVI (produced at runtime) |
| `vuln_001_result.txt` | ffmpeg stdout+stderr + ASAN log (produced at runtime) |
| `vuln_001_status.txt` | One-line verdict + explanation |
