# Vulnerability Notes: dvb_encode_rle8 Off-by-One (dvbsubenc.c:225)

## Summary

**File:** `libavcodec/dvbsubenc.c`  
**Function:** `dvb_encode_rle8()`  
**Line:** 225  
**Type:** Off-by-one heap buffer overflow (latent / context-dependent)

## Root Cause

The per-line buffer size check in `dvb_encode_rle8` underestimates the worst-case overhead by 1 byte:

```c
// Line 224 comment says: "Worst case line is 12 bits per value, + 3 bytes overhead"
// Line 225:
if (buf_size * 8 < w * 12 + 24)   // 24 bits = 3 bytes overhead (WRONG)
    return AVERROR_BUFFER_TOO_SMALL;
```

The actual worst-case output per line is:

| Byte | Content | Purpose |
|------|---------|---------|
| 1 | `0x12` | data_type = 8-bpp pixel string |
| up to `w*1.5` | pixel data | encoded pixels |
| 2 | `0x00 0x00` | end-of-string marker |
| 1 | `0xF0` | end-of-display-line marker |

The fixed overhead is 4 bytes (32 bits), not 3 bytes (24 bits). The correct check should be:

```c
if (buf_size * 8 < w * 12 + 32)   // 32 bits = 4 bytes overhead (CORRECT)
```

## Trigger Conditions

To reach the off-by-one write at line 267 (`*q++ = 0xf0`):

1. **Subtitle rect width = 2** with alternating pixel pattern `[nonzero, 0]`:
   - Pixel 0 is nonzero → `*q++ = color` (1 byte)
   - Pixel 1 is zero → `*q++ = 0x00; *q++ = 1;` (2 bytes, run-of-1 for color 0)
   - End of line → `*q++ = 0x00; *q++ = 0x00; *q++ = 0xf0;` (3 bytes)
   - Plus data-type byte → **7 bytes total per row**

2. **8-bpp encoding path** must be selected (`dvb_encode_rle8` chosen):
   - Requires `nb_colors > 16` (e.g., rect decoded from an 8-bpp DVB subtitle region)

3. **Buffer exactly 6 bytes remaining** when the vulnerable row is encoded:
   - The check: `6 * 8 = 48`, and `2 * 12 + 24 = 48` → `48 < 48` is **FALSE** → check passes
   - Then 7 bytes are written → **1-byte write past the safe boundary** at the `*q++ = 0xf0` write

## Why ffmpeg CLI Does Not Crash

The ffmpeg binary (`do_subtitle_out` in `fftools/ffmpeg_enc.c`) allocates:

```c
int subtitle_out_max_size = 1024 * 1024;  // 1 MB
ret = av_new_packet(pkt, subtitle_out_max_size);
```

After encoding all headers for our minimal 1-rect subtitle, approximately 999 KB remain when `dvb_encode_rle8` is called. Writing 7 bytes when 6 are "checked" causes no real memory corruption because the allocation is far from exhausted.

## Exploitability

The bug becomes a real heap-buffer-overflow when `avcodec_encode_subtitle` is called with a tight buffer:

```c
// Minimal safe buffer for w=2 one-row subtitle according to the buggy check:
uint8_t buf[headers_size + 6];   // 6 bytes = passes the check
avcodec_encode_subtitle(ctx, buf, sizeof(buf), &sub);
// → writes 7 bytes → 1-byte overflow at the last *q++ = 0xf0
```

With ASAN this produces:
```
=================================================================
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
WRITE of size 1 at 0x... thread T0
    #0 dvb_encode_rle8 (dvbsubenc.c:267)
    #1 dvbsub_encode   (dvbsubenc.c:487)
    #2 avcodec_encode_subtitle (encode.c:213)
```

## Input File Design

`vuln_001_input.ts` is a minimal MPEG-TS file (1880 bytes, 10 TS packets) containing:
- One PAT packet and one PMT packet (DVB subtitle descriptor, PID=256, page_id=1)
- Eight DVB subtitle PES packets with varying page versions (0–7), each carrying:
  - **Page Composition**: region 0 at (0, 0), page_state=mode_change
  - **Region Composition**: 2×2 pixels, 8-bpp depth (depth byte 0x6F), CLUT 0
  - **CLUT Definition**: index 0=transparent, index 1=opaque white (8-bpp entries)
  - **Object Data**: 2×2 bitmap, top-field=[1,0], bottom-field=[1,0]
  - **End of Display Set**

Using distinct page versions (0–7) across the 8 packets ensures the
`ctx->version == version` early-return check in `dvbsub_parse_page_segment`
does not skip any packet, and using a single PAT/PMT avoids the
"Demuxer context update while decoder is open" disruption that occurs
when repeated PMTs with the same version are seen.

When ffmpeg re-encodes with `-c:s dvbsub`, the decoder produces `rect->nb_colors=256`
(from region depth=8), selecting `dvb_encode_rle8`. Both the top and bottom field
encoding calls trigger the buggy check on each of the 7 decoded frames.

## Fix

Change line 225 in `libavcodec/dvbsubenc.c`:

```c
// Before (wrong):
if (buf_size * 8 < w * 12 + 24)

// After (correct):
if (buf_size * 8 < w * 12 + 32)
```
