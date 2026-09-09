# VULN 001: Heap Overflow in PSD BITMAP Decode

## PoC Approach

The PoC crafts a minimal PSD file with:
- `color_mode = 0` (BITMAP / 1-bit monochrome)
- `channel_depth = 1`, `channel_count = 1`
- `compression = 0` (RAW — no RLE)
- `width = 64`, `height = 64`
- Image data payload = `width × height = 4096` bytes

## Trigger Path

1. `decode_header()` parses the PSD header and sets `s->width=64`, `s->height=64`,
   `s->channel_depth=1`, `s->color_mode=PSD_BITMAP`, `s->compression=PSD_RAW`.

2. `decode_frame()` line 338:
   ```c
   s->line_size = s->width + 7 >> 3;
   ```
   Due to the operator precedence bug this evaluates as:
   - Claimed buggy interpretation: `s->width + (7 >> 3) = 64 + 0 = 64`
   - Correct formula (intended): `(s->width + 7) >> 3 = 8`

3. Line 446:
   ```c
   s->uncompressed_size = s->line_size * s->height * s->channel_count;
   ```
   If `s->line_size = 64` (buggy): `uncompressed_size = 64 × 64 × 1 = 4096`.

4. Line 463: bounds check passes because we provide exactly 4096 image bytes.

5. `ff_get_buffer()` allocates an AVFrame for `AV_PIX_FMT_MONOWHITE`. For
   width=64, the allocated row size is `ceil(64/8) = 8` bytes.

6. Lines 551–558 (planar copy loop):
   ```c
   for (y = 0; y < s->height; y++) {
       memcpy(ptr, ptr_data, s->line_size);   // line 555: copies 64 bytes
       ptr += picture->linesize[plane_number]; // advances 8 bytes
       ptr_data += s->line_size;
   }
   ```
   Each `memcpy` writes 64 bytes into an 8-byte row buffer → **56-byte heap overflow per row**.

## Expected Behavior

With ASAN enabled, this should produce:
```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
WRITE of size 64 at ...
```
The overflow writes 56 × 64 = 3584 bytes past the end of the allocated frame buffer, which is highly likely to corrupt adjacent heap objects and trigger an ASAN report or a crash.
