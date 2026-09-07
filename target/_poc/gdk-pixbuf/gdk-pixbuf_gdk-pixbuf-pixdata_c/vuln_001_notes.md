# VULN-001: Heap Buffer Overflow via RLE Control Byte 0x80

## Status: VERIFIED_CRASH

## Vulnerability Location
- File: `gdk-pixbuf/gdk-pixbuf/gdk-pixdata.c`, lines 463-483
- Function: `gdk_pixbuf_from_pixdata()`

## Root Cause

When the RLE control byte is `0x80` (value 128), the decoder computes:

```c
guint length = *(rle_buffer++);  // length = 0x80 = 128
if (length & 128)
{
    length = length - 128;   // 128 - 128 = 0  (guint)
    check_overrun = image_buffer + length * bpp > image_limit;
    // 0 * 3 = 0, so check_overrun = FALSE (no guard kicks in)
    if (bpp < 4)  /* RGB */
        do {
            memcpy (image_buffer, rle_buffer, 3);
            image_buffer += 3;
        } while (--length);  // --0 wraps guint to UINT_MAX (~4 billion)
```

The `do { } while (--length)` construct executes the body **before** checking the condition.
When `length == 0`, the first iteration runs unconditionally, then `--length` underflows the
unsigned integer from 0 to `UINT_MAX` (4294967295). The loop then runs approximately 4 billion
more iterations, writing 3 bytes at a time into heap memory far beyond the allocated buffer.

## Trigger Path

```
gdk_pixbuf_new_from_file()          (binary entry, reads .gdkp file)
  -> _gdk_pixbuf_generic_image_load()
    -> generic_load_incrementally()
      -> pixdata_image_load_increment()  (io-pixdata.c: pixdata file loader)
        -> try_load()
          -> gdk_pixdata_deserialize()
          -> gdk_pixbuf_from_pixdata()   <- VULNERABLE FUNCTION
            -> memcpy() HEAP BUFFER OVERFLOW
```

The io-pixdata.c module is compiled statically into `libgdk_pixbuf-2.0.so`. Any file
starting with the magic bytes `GdkP` is recognized as a GdkPixdata image and routed
through this path by `gdk_pixbuf_new_from_file()`.

## PoC Approach

Generated a 28-byte `.gdkp` binary file with a crafted 24-byte GdkPixdata header plus
4 bytes of malicious RLE pixel data.

### Header Values

| Field         | Value        | Notes                                          |
|---------------|--------------|------------------------------------------------|
| magic         | 0x47646b50   | "GdkP" — triggers io-pixdata loader            |
| length        | 28           | header(24) + pixel_data(4)                     |
| pixdata_type  | 0x02010001   | ENCODING_RLE(0x02<<24) | SAMPLE_WIDTH_8(0x01<<16) | COLOR_TYPE_RGB(0x01) |
| rowstride     | 12           | width(4) * 3 bytes/pixel                       |
| width         | 4            |                                                |
| height        | 4            |                                                |
| pixel_data    | 80 ff 00 00  | 0x80 = RLE constant run with underflow trigger |

### Why Validation Passes

`gdk_pixdata_deserialize()` only validates:
- Magic bytes (`GdkP`) -- pass
- `length >= 24` (header size) -- 28 >= 24, pass
- `width >= 1`, `height >= 1`, `rowstride >= width` -- all pass
- `stream_length >= pixdata->length - 24` -- 4 >= 4, pass
- Valid color type, sample width, encoding fields -- all valid

The `pixdata_get_length()` sanity-check function (which does detect `chunk_length == 0`
as corrupt) is only called from `gdk_pixdata_from_pixbuf()` (the serializer), NOT from
`gdk_pixbuf_from_pixdata()` (the deserializer/decoder). The decoder has no such guard.

## ASAN Confirmation

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x504000000680
WRITE of size 3 at 0x504000000680 thread T0
  #0 __interceptor_memcpy
  #1 gdk_pixbuf_from_pixdata  (libgdk_pixbuf-2.0.so.0+0xacede)
  #2 try_load
  #3 pixdata_image_load_increment
  ...

0x504000000680 is located 0 bytes to the right of 48-byte region
[0x504000000650, 0x504000000680)
```

The 48-byte region = 4 * 4 * 3 (width * height * bpp) — exactly the allocated image buffer.
The first out-of-bounds write occurs immediately after the buffer is exhausted (after 16
valid 3-byte writes = 48 bytes consumed).

## Files

- `vuln_001_gen.py` — generates `vuln_001.gdkp` (28-byte malicious file)
- `vuln_001_run.sh` — runs the binary with ASAN and checks for crash
- `vuln_001.gdkp` — the malicious GdkPixdata binary file
- `vuln_001_status.txt` — `VERIFIED_CRASH`
- `asan_001.log.*` — ASAN output logs
