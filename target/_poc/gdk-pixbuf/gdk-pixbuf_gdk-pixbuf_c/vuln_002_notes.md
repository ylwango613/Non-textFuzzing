# VULN 002 – Heap OOB Read via Unbounded rle_buffer in gdk_pixbuf_from_pixdata

## Status: VERIFIED_CRASH

## Summary

A crafted GdkPixdata file with a declared image size far larger than the
provided RLE pixel data causes `gdk_pixbuf_from_pixdata()` to read past the
end of the heap-allocated pixel data buffer.  AddressSanitizer confirms a
**heap-buffer-overflow READ** of 3 bytes.

## Root Cause

In `gdk-pixbuf/gdk-pixdata.c`, `gdk_pixbuf_from_pixdata()` decodes RLE data
into an output buffer.  The loop condition only checks that the *output* buffer
has not been filled:

```c
const guint8 *rle_buffer = pixdata->pixel_data;   // input — only 4 bytes
guint8 *image_buffer = data;
guint8 *image_limit  = data + pixdata->rowstride * pixdata->height; // 30 000 bytes

while (image_buffer < image_limit)       // terminates on OUTPUT side only
{
    guint length = *(rle_buffer++);      // OOB read after pixel_data exhausted
    ...
    memcpy(image_buffer, rle_buffer, 3); // OOB read confirmed by ASAN
    ...
}
```

There is **no bounds check** on `rle_buffer` against the end of `pixel_data`.
`gdk_pixdata_deserialize()` validates that the serialized `length` field
matches the stream length, but does not validate that the RLE content is
sufficient to fill the declared image dimensions.  Once the 4 bytes of RLE
input are consumed, the decoder reads from adjacent heap memory.

## GdkPixdata Binary Format (big-endian)

| Offset | Size | Field        | Our value       |
|--------|------|--------------|-----------------|
| 0      | 4    | magic        | 0x47646b50 "GdkP" |
| 4      | 4    | length       | 0x0000001c (28) |
| 8      | 4    | pixdata_type | 0x02010001 (RLE + 8-bit samples + RGB) |
| 12     | 4    | rowstride    | 0x0000012c (300) |
| 16     | 4    | width        | 0x00000064 (100) |
| 20     | 4    | height       | 0x00000064 (100) |
| 24     | 4    | pixel_data   | 01 ff 00 00 (4 bytes only) |

Correct `pixdata_type` encoding (from gdk-pixdata.h):
- `GDK_PIXDATA_ENCODING_RLE   = 0x02 << 24 = 0x02000000`
- `GDK_PIXDATA_SAMPLE_WIDTH_8 = 0x01 << 16 = 0x00010000`
- `GDK_PIXDATA_COLOR_TYPE_RGB = 0x01`
- Combined: `0x02010001`

## Attack Path

```
crafted .gdkp file
  → gdk_pixbuf_new_from_file()
  → _gdk_pixbuf_generic_image_load()
  → pixdata_image_load_increment()          (io-pixdata.c)
  → gdk_pixdata_deserialize()               (gdk-pixdata.c)  – passes, 4 bytes accepted
  → gdk_pixbuf_from_pixdata()               (gdk-pixdata.c)
  → RLE decode loop reads past pixel_data   – HEAP OOB READ
  → memcpy() touches address past allocation boundary
```

## ASAN Output (excerpt)

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50c000000840
READ of size 3
    #1 in gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0)
    #2 in try_load (libgdk_pixbuf-2.0.so.0)
    #3 in pixdata_image_load_increment (libgdk_pixbuf-2.0.so.0)
0x50c000000840 is located 0 bytes to the right of 128-byte region
```

## Impact

An attacker who can supply a malformed `.gdkp` image file can trigger an
out-of-bounds heap read.  Depending on heap layout this may leak adjacent heap
contents (information disclosure) or, under certain allocator conditions,
trigger further memory corruption.  Any application that calls
`gdk_pixbuf_new_from_file()` (or any other GdkPixbuf loading API) on
attacker-controlled pixdata files is affected.

## Notes on Initial Failure

The first attempt used `pixdata_type = 0x00020001`.  The deserializer rejected
this with "Image format unknown" because the field is interpreted in three
independent bit fields, not as a packed short:

- `color_type  = type & 0x000000ff` must be 0x01 (RGB) or 0x02 (RGBA)
- `sample_width = type & 0x000f0000` must be 0x00010000 (8-bit)
- `encoding    = type & 0x0f000000` must be 0x01000000 (RAW) or 0x02000000 (RLE)

With `0x00020001`: `sample_width = 0` and `encoding = 0` → invalid format.
After correcting to `0x02010001` the file is accepted and the crash fires.
