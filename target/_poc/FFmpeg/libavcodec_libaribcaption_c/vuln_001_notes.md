# PoC Notes: FFmpeg libaribcaption.c clut_init() Heap OOB Write

## Vulnerability Summary

- **File**: `libavcodec/libaribcaption.c`
- **Function**: `clut_init()`, lines 278-292
- **CWE**: CWE-787 (Out-of-bounds Write)
- **Type**: Heap buffer overflow (write)

## Root Cause

`ctx->clut` is allocated as exactly `AVPALETTE_COUNT` (256) `uint32_t` entries.

In `clut_init()`:
```c
for (int i = 1; i < region->char_count; i++) {
    if (region->chars[i].text_color != text_color) {
        rgba = ARIBCC_COLOR_TO_CLUT_RGBA(region->chars[i].text_color, ...);
        if (clut_find(ctx, rgba) < 0) {
            ctx->clut[ctx->clut_idx++] = rgba;   // line 283: no bounds check
            ...
        }
    }
    if (region->chars[i].back_color != back_color) {
        rgba = ARIBCC_COLOR_TO_CLUT_RGBA(region->chars[i].back_color, ...);
        if (clut_find(ctx, rgba) < 0) {
            ctx->clut[ctx->clut_idx++] = rgba;   // line 291: no bounds check
            ...
        }
    }
    ...
}
```

Note that `stroke_color` writes at lines 299-300 DO have a bounds check (`if (ctx->clut_idx < AVPALETTE_COUNT)`), but `text_color` (line 283) and `back_color` (line 291) do NOT, enabling OOB write.

With 127+ characters each having a unique `text_color` or `back_color`, `clut_idx` will exceed 256 causing writes past the end of the heap-allocated CLUT buffer.

## Trigger Path

```
ffmpeg -i crafted.ts -sub_type bitmap -f null -
  -> demux MPEG-TS, find ARIB caption stream (stream_type=0x06 + ARIB descriptor)
  -> aribcaption_decode() [line 844]
  -> aribcc_decoder_decode() [external libaribcaption library]
  -> aribcaption_trans_bitmap_subtitle() [line 851]
  -> clut_init() [line 254]
  -> OOB write at ctx->clut[clut_idx++] when clut_idx >= 256
```

**Critical**: Must use `-sub_type bitmap`. The default ASS mode does NOT call `clut_init()` and does NOT trigger this path.

## Prerequisites

1. FFmpeg must be compiled with libaribcaption support:
   ```
   ffmpeg -decoders 2>/dev/null | grep -i arib
   ```
   Expected output contains `arib_std_b24_caption` or similar.

2. The external `libaribcaption` library must be installed on the system.

## Files

- `vuln_001_gen.py`: Generates `vuln_001_input.ts` — a crafted MPEG-TS with ARIB STD-B24 caption data containing 200 characters with unique color pairs.
- `vuln_001_run.sh`: Runs the PoC via ffmpeg.

## MPEG-TS / ARIB Packet Structure Used

```
MPEG-TS stream:
  PAT: program 1 -> PMT PID 0x1000
  PMT:
    PID 0x100: stream_type=0x02 (video placeholder)
    PID 0x200: stream_type=0x06 + stream_identifier_descriptor(component_tag=0x30)
               -> ARIB caption stream
  PES on PID 0x200:
    stream_id=0xBD (private stream 1)
    ARIB data:
      data_identifier=0x80
      data_group_id=0x40: caption management (declares language)
      data_group_id=0x41: caption statement with 200 chars, each with unique COL codes
```

## Status

**SKIPPED** on this build — libaribcaption decoder not compiled into FFmpeg binary.

To reproduce when libaribcaption is available:
1. Build FFmpeg with `--enable-libaribcaption`
2. Install libaribcaption: https://github.com/xqq/libaribcaption
3. Run `./vuln_001_run.sh`
4. With ASAN: expect `heap-buffer-overflow` in `clut_init` writing past `ctx->clut[255]`
