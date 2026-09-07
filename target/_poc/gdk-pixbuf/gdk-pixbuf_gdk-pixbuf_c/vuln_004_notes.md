# VULN 004 – gdk-pixbuf: Infinite Loop DoS via RLE Literal-Run Zero-Length

## Vulnerability Summary

**Type**: Heap-buffer-overflow (OOB read) + unbounded CPU loop (DoS)  
**Location**: `gdk_pixbuf_from_pixdata()` in `gdk-pixbuf/gdk-pixdata.c`, lines 485-494  
**Impact**: Denial of Service – CPU exhaustion and heap OOB read  
**CVE**: N/A (internal audit finding)

## Root Cause

In the RLE decoding loop inside `gdk_pixbuf_from_pixdata()`:

```c
while (image_buffer < image_limit)
{
    guint length = *(rle_buffer++);   // reads 0x00, rle_buffer advances by 1
    if (length & 128)
        { /* repeat-run */ }
    else
    {
        length *= bpp;                // 0 * 3 = 0
        check_overrun = image_buffer + length > image_limit;   // 0 > 48 → FALSE
        if (check_overrun)
            length = image_limit - image_buffer;
        memcpy(image_buffer, rle_buffer, length);   // memcpy(..., 0) → no-op
        image_buffer += length;      // += 0 → no progress
        rle_buffer   += length;      // += 0 → no additional progress
    }
}
```

When the first RLE byte is `0x00`:
- `length = 0` (literal-run, count=0)
- `length *= bpp` → `0 * 3 = 0`
- `memcpy(image_buffer, rle_buffer, 0)` → does nothing
- `image_buffer += 0` → **no progress** toward `image_limit`
- `rle_buffer += 0` → no extra advance (but `rle_buffer++` already consumed one byte)

The outer `while (image_buffer < image_limit)` condition NEVER becomes false.
With a pixel_data buffer filled with `0x00` bytes:
- Each iteration reads one byte (advancing `rle_buffer` by 1)
- `image_buffer` never advances
- The loop runs through all `N` zero bytes, then reads **1 byte past the end** of the heap buffer
- ASAN detects: `heap-buffer-overflow READ of size 1`

## Attack Path

```
crafted .gdkp file → gdk_pixdata_deserialize() [passes, header valid]
                   → gdk_pixbuf_from_pixdata() → RLE loop → infinite iterations
                                                           → heap OOB read
```

## Trigger Conditions

- `pixdata_type = 0x02010001` (GDK_PIXDATA_ENCODING_RLE | GDK_PIXDATA_SAMPLE_WIDTH_8 | GDK_PIXDATA_COLOR_TYPE_RGB)
- `pixel_data` = one or more `0x00` bytes (literal-run count=0)
- With a 1024-byte all-zero pixel_data block, ASAN reports heap-buffer-overflow after reading past the buffer

## Note on pixdata_type Encoding

The vulnerability description uses `0x00020001` as the pixdata_type, but the correct constant values are:
- `GDK_PIXDATA_ENCODING_RLE  = 0x02 << 24 = 0x02000000`
- `GDK_PIXDATA_SAMPLE_WIDTH_8 = 0x01 << 16 = 0x00010000`
- `GDK_PIXDATA_COLOR_TYPE_RGB = 0x01`
- Combined: `0x02010001`

`0x00020001` would fail `gdk_pixdata_deserialize()`'s format validation check.

## PoC Files

| File | Description |
|------|-------------|
| `vuln_004_gen.py` | Generates `vuln_004.gdkp` with all-zero RLE pixel data |
| `vuln_004_trigger.c` | C harness calling `gdk_pixdata_deserialize` + `gdk_pixbuf_from_pixdata` directly |
| `vuln_004_trigger` | Compiled binary (ASAN+UBSAN) |
| `vuln_004.gdkp` | Crafted 1048-byte file (24-byte header + 1024 zero bytes) |
| `vuln_004_run.sh` | Full run script including compile + execute |
| `vuln_004_result.txt` | Output with ASAN crash log |

## Confirmed Output (ASAN)

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x519000000e98
READ of size 1 at 0x519000000e98 thread T0
    #0 in gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0+0xacdd8)

0x519000000e98 is located 0 bytes to the right of 1048-byte region [...]
```

## Without ASAN

In a non-instrumented build, `rle_buffer` reads past the end of the pixel_data buffer
into adjacent heap memory. If that memory contains zeros (common with heap allocators),
the loop continues reading zero bytes, keeping `image_buffer` stationary, resulting in
near-infinite CPU spinning. This is the pure DoS aspect of the vulnerability.

## Fix

Add a check for `length == 0` in the literal-run branch:

```c
else
{
    if (length == 0) {
        g_set_error_literal(error, GDK_PIXBUF_ERROR,
                            GDK_PIXBUF_ERROR_CORRUPT_IMAGE,
                            _("Image pixel data corrupt"));
        g_free(data);
        return NULL;
    }
    length *= bpp;
    ...
}
```

Note: `pixdata_get_length()` already has this check (`if (!chunk_length) return 0`),
but `gdk_pixbuf_from_pixdata()` does not validate against `pixdata_get_length()` before
entering the RLE loop.
