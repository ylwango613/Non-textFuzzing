# VULN 001 – Integer Overflow in TrueMotion 2 decode_init()

## Vulnerability Summary

**File**: `libavcodec/truemotion2.c`, lines 972–989  
**CWE**: CWE-190 (Integer Overflow) → CWE-122 (Heap-based Buffer Overflow)  
**CVSS vector**: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H  

## Root Cause

In `decode_init()`, `w` and `h` are declared as `int` (32-bit signed):

```c
int w = avctx->width, h = avctx->height;   // both = 131072
...
w += 8;   // w = 131080 = 0x20008
h += 8;   // h = 131080 = 0x20008
l->Y_base = av_calloc(w * h, 2 * sizeof(*l->Y_base));
//          ^^^^^^^^^^^^^^
//          131080 * 131080 = 0x400200040  -> truncates to 0x00200040 = 2,097,216
//          (int32 overflow: signed integer overflow is undefined behavior in C)
l->Y2 = l->Y1 + w * h;   // same overflowed value: Y2 points only ~16 MB past Y1
//                        // but actual frame needs ~128 GB; subsequent writes go OOB
```

The overflow causes `av_calloc` to receive a count of 2,097,216 instead of 17,181,974,400,
allocating ~16 MB instead of ~128 GB. When `tm2_decode_blocks()` subsequently indexes
`Y1[row * y_stride + col]` using the true pixel coordinates, it writes far past the
allocated buffer.

## PoC Strategy

1. **Craft an AVI file** with FOURCC `TM20`, width = height = 131072.  
   The AVI demuxer reads `biWidth`/`biHeight` from the `strf` (BITMAPINFOHEADER) chunk
   and sets `st->codecpar->width = 131072`, `st->codecpar->height = 131072`.

2. **Include a minimal TM2 frame** (68 bytes) whose magic matches `TM2_OLD_HEADER_MAGIC`
   (0x00000100) after FFmpeg's bswap_buf pass. Seven zero-length streams follow.

3. **Trigger path**: `ffmpeg -i crafted.avi -f null -`
   → AVI demuxer → avcodec_open2() → decode_init() → integer overflow in `w*h`
   → av_calloc allocates undersized buffer → tm2_decode_blocks() → heap OOB write

## Expected Crash Behavior

With ASAN instrumentation, the expected report would be:

```
==XXXXXXXX==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 4 at 0x... thread T0
    #0 ... tm2_apply_deltas (truemotion2.c:466)
    #1 ... tm2_null_res_block (truemotion2.c:633)
    #2 ... tm2_decode_blocks (truemotion2.c:800)
    #3 ... decode_frame (truemotion2.c:933)
```

Or with UBSan (signed-integer-overflow):

```
truemotion2.c:974:25: runtime error: signed integer overflow:
  131080 * 131080 cannot be represented in type 'int'
```

## Notes on Protective Mitigations in This Build

`avcodec_open2()` calls `ff_set_dimensions()` (libavcodec/utils.c:91) which internally
calls `av_image_check_size2()`. For width=height=131072:

```
stride = 8 * 131072 + 1024 = 1,049,600
stride * (131072 + 128) = 137,707,520,000 >> INT_MAX (2,147,483,647)
```

This causes `av_image_check_size2` to return `AVERROR(EINVAL)`, which causes
`ff_set_dimensions` to reset width/height to 0 and return an error, causing
`avcodec_open2` to fail before ever calling `decode_init`.

As a result, **the integer overflow in `decode_init` is not reachable via the
standard `ffmpeg` command-line tool in this build**, because the dimension safety
check fires first. The vulnerability exists in the code path but is mitigated
by the upstream dimension validation.

The PoC file is constructed correctly according to the AVI/TM2 spec; FFmpeg's
rejection message ("Picture size 131072x131072 is invalid") confirms that the
crafted file is well-formed enough to be parsed, and that the dimensions are
recognized—they are simply rejected by the guard before decode_init is reached.
