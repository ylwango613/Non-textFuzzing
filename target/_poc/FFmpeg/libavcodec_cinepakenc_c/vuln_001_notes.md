# VULN 001 — Integer Overflow → Heap Underalloc in cinepak_encode_init

## Vulnerability Summary

**File**: `libavcodec/cinepakenc.c`, lines 181–189  
**Type**: CWE-190 (Integer Overflow) → CWE-122 (Heap-based Buffer Overflow)

### Root Cause

In `cinepak_encode_init`, allocation sizes are computed using signed 32-bit integer arithmetic:

```c
// Line 182
s->codebook_input = av_malloc_array(
    (avctx->pix_fmt == AV_PIX_FMT_RGB24 ? 6 : 4)
        * (avctx->width * avctx->height) >> 2,
    sizeof(*s->codebook_input));

// Line 189 (inside loop for 4 pict_bufs)
s->pict_bufs[x] = av_malloc(
    (avctx->pix_fmt == AV_PIX_FMT_RGB24 ? 6 : 4)
        * (avctx->width * avctx->height) >> 2);
```

With `pix_fmt=AV_PIX_FMT_RGB24`, `width=4`, `height=178956972`:

```
step 1: width * height = 4 * 178956972 = 715,827,888   (fits in int32)
step 2: 6 * 715,827,888 = 4,294,967,328                (overflows int32!)
         4,294,967,328 mod 2^32 = 32  →  stored as 32 in signed int32
step 3: 32 >> 2 = 8                                     (operand size)
```

Result: `av_malloc_array(8, sizeof(int))` → **32 bytes** allocated.

During encoding, the same dimensions are used (without overflow check) to iterate over all macroblocks: `mb_count = width * height / 16 = ~44.7 million`. The encoder writes to `codebook_input` and `pict_bufs` using indices derived from mb_count, causing massive heap writes beyond the 32-byte allocation.

### Trigger Condition

- Pixel format: `AV_PIX_FMT_RGB24` (selected when input is 24-bit color or the encoder auto-selects RGB24)
- Dimensions where `6 * (width * height)` overflows int32 to a small positive value

## PoC Approach

### Approach A: Crafted AVI Input

`vuln_001_gen.py` creates a minimal RIFF/AVI file with:
- Width=4, Height=178956972 in the stream header (avih + strh + strf/BITMAPINFOHEADER)
- Codec type: CVID (Cinepak)
- 1 dummy cinepak frame (10 bytes, 0 strips)
- idx1 index entry

The command `ffmpeg -i vuln_001_input.avi -c:v cinepak -f avi /dev/null` should:
1. Parse the AVI headers, obtaining width=4 and height=178956972
2. Open the cinepak encoder for the output stream (triggers `cinepak_encode_init`)
3. The overflow occurs in init, allocating 32-byte buffers
4. During encoding of the frame, OOB heap writes occur

**Known blocker**: FFmpeg's `av_image_check_size2()` in `libavutil/imgutils.c` (line 301) checks:
```c
stride*(h + 128ULL) >= INT_MAX
```
where `stride = 8*width + 1024`. With width=4, height=178956972:
`1056 * 178957100 = 188,978,697,600 >= 2,147,483,647` → check fails.

FFmpeg logs "Ignoring invalid width/height values" and resets dimensions to 0, preventing the encoder init from seeing the overflow-triggering dimensions. This size check was likely added as a mitigation.

### Approach B: lavfi Synthetic Source

`ffmpeg -f lavfi -i "color=size=4x178956972:rate=1" -frames:v 1 -c:v cinepak -f avi /dev/null`

Same dimensions, same expected blocker (size check in av_image_check_size2).

### Approach C: rawvideo + Scale Filter

Using a 4x4 input with `-vf scale=4:178956972` to force the encoder to use the target dimensions. The scale filter would also fail the size check when allocating the output frame.

## Analysis

The vulnerability exists in the source code (`cinepakenc.c`) but is protected at runtime by `av_image_check_size2()`. This protection resets invalid dimensions to 0 rather than returning an error (avcodec.c line 244: `ff_set_dimensions(avctx, 0, 0)`), which means ffmpeg continues with 0×0 dimensions instead of the overflow-triggering values.

The vulnerability would be exploitable in contexts where:
- The encoder context is populated without going through the size check
- Or on systems/builds where the size check is absent/different

## Files

| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001_input.avi` with overflow-triggering dimensions |
| `vuln_001_run.sh` | Runs ffmpeg with ASAN and tests all three approaches |
| `vuln_001_notes.md` | This document |
| `vuln_001_result.txt` | Output from the PoC run |
| `vuln_001_status.txt` | One-line verdict |
