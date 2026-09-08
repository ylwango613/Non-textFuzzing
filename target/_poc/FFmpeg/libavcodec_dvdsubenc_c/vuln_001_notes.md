# VULN-001 PoC Notes: Integer Overflow in dvdsubenc.c

## Vulnerability Summary

**File:** `libavcodec/dvdsubenc.c`, function `dvdsub_encode()`, line 344

**Vulnerable Code:**
```c
// worst case memory requirement: 1 nibble per pixel..
if ((q - outbuf) + vrect.w * vrect.h / 2 + 17 + 21 > outbuf_size) {
    av_log(NULL, AV_LOG_ERROR, "dvd_subtitle too big\n");
    ret = AVERROR_BUFFER_TOO_SMALL;
    goto fail;
}
```

**Root Cause:** `vrect.w * vrect.h` uses signed 32-bit integer multiplication. When `w * h > INT_MAX` (2,147,483,647), the product overflows to a negative value. The check then evaluates to a small negative number (which is less than `outbuf_size`), causing the size guard to pass incorrectly. Subsequently, `dvd_encode_rle()` writes RLE-encoded data assuming the large dimensions, writing past the end of the 1MB output buffer allocated by `fftools/ffmpeg_enc.c`.

**Overflow Example:** w=46341, h=46342: product = 2,147,534,622 > INT_MAX, overflows to -2,147,432,674 (as signed 32-bit).

## PoC Approach

We craft a minimal MKV file containing an S_HDMV/PGS subtitle stream. The PGS format allows specifying video dimensions and object dimensions via segment headers.

**Trigger command:**
```bash
ffmpeg -i vuln_001_input.mkv -c:s dvdsub -f vob /dev/null
```

## Analysis of Exploitability

### Why the ideal trigger (w=46341, h=46342) does not work in practice

The PGS subtitle decoder (`pgssubdec.c`) validates dimensions in two places:

1. **PCS (Presentation Composition Segment):** `ff_set_dimensions(avctx, video_w, video_h)` calls `av_image_check_size2()` with `AV_PIX_FMT_NONE`. The check:
   ```
   stride = 8*w + 1024
   stride * (h + 128) >= INT_MAX  →  FAIL
   ```
   For w=46341: stride=371,752. For h=46342: stride*(h+128) = 2,201,051,550 > INT_MAX → **rejected**.
   When rejected, `avctx->width` and `avctx->height` are set to 0.

2. **ODS (Object Definition Segment):** Check `avctx->width < obj_w`. With `avctx->width=0`, any nonzero width fails this check → object not created.

3. **avcodec_open2():** Even if codec parameters had large dimensions, they are cleared:
   ```c
   if (av_image_check_size2(avctx->width, avctx->height, ...) < 0)
       ff_set_dimensions(avctx, 0, 0);  // resets to zero
   ```

### Mathematical constraint

`av_image_check_size2` with `AV_PIX_FMT_NONE` imposes:
```
(8*w + 1024) * (h + 128) < INT_MAX
```
The maximum achievable `w*h` under this constraint is approximately 264M pixels (near w≈h≈16256), which is only ~12% of INT_MAX (2.1B). The integer overflow in dvdsubenc requires `w*h > INT_MAX`.

**Conclusion:** The existing `av_image_check_size` guards form a mathematical impossibility: any dimension pair that would cause the dvdsubenc overflow is rejected by the PGS decoder before reaching the encoder.

### What the PoC demonstrates

1. **Overflow dimensions (w=46341, h=46342):** PGS decoder rejects the PCS segment. The subtitle is not created and never reaches dvdsubenc.

2. **Valid large dimensions (w=1025, h=2046):** `w*h = 2,097,150`. These pass av_image_check_size constraints and reach dvdsubenc. The size check `4 + 2097150/2 + 38 = 1,048,625 > 1,048,576` correctly returns `BUFFER_TOO_SMALL` (error, not OOB write). This confirms the code path is reachable.

## Files

- `vuln_001_gen.py`: Python script that constructs the crafted MKV files
- `vuln_001_input_overflow.mkv`: MKV with w=46341, h=46342 (fails decoder validation)
- `vuln_001_input_valid.mkv`: MKV with w=1025, h=2046 (reaches dvdsubenc, returns error)
- `vuln_001_input.mkv`: Primary PoC input (same as valid variant)
- `vuln_001_run.sh`: Script that runs both test cases and captures output

## Theoretical Trigger

The vulnerability WOULD be triggered if a subtitle decoder produced an `AVSubtitleRect` with `w=46341, h=46342` without av_image_check_size validation. This could happen in:
- A hypothetical decoder that reads dimensions as raw 16-bit integers without validation
- A version of FFmpeg where the av_image_check_size guards were not yet in place
- A future codec/format that bypasses the standard dimension validation path
