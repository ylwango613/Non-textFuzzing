# VULN 002 - Out-of-Bounds Heap Read in gdk_pixbuf_from_pixdata (RLE decoder)

## Status: VERIFIED_CRASH

## Vulnerability Summary

- **CWE**: CWE-125 (Out-of-Bounds Read)
- **Function**: `gdk_pixbuf_from_pixdata()` in `gdk-pixdata.c`, lines 452-503
- **Root Cause**: The RLE decode loop only checks whether the output buffer (`image_buffer < image_limit`) is filled, but never verifies that `rle_buffer` is still within the bounds of `pixel_data`. When pixel_data is exhausted before the output is filled, `rle_buffer` reads past the heap allocation.

Vulnerable loop pattern:
```c
while (image_buffer < image_limit) {
    guint length = *(rle_buffer++);  // NO bounds check on rle_buffer
    ...
}
```

## PoC Input File

- **File**: `vuln_002.gdkp` (29 bytes)
- **Format**: GdkPixdata binary stream (big-endian header + RLE pixel_data)

Header fields:
| Field         | Value      | Notes                            |
|--------------|------------|----------------------------------|
| magic        | 0x47646B50 | "GdkP"                          |
| length       | 29         | 24-byte header + 5-byte payload  |
| pixdata_type | 0x02010002 | RGBA, 8-bit samples, RLE encoded |
| rowstride    | 400        | width * 4 bytes per pixel        |
| width        | 100        |                                  |
| height       | 100        |                                  |

pixel_data (5 bytes):
- `0xFF` = constant run header, length = 0xFF - 128 = 127 pixels
- `0xFF 0xFF 0xFF 0xFF` = RGBA pixel (opaque white)

This run writes only 127 pixels x 4 bytes = 508 bytes to the output buffer.
The declared image requires 100 x 400 = 40,000 bytes total.
After consuming 5 bytes of pixel_data, `rle_buffer` reads past the heap allocation on the next loop iteration.

## ASAN Output

```
==133124==ERROR: AddressSanitizer: unknown-crash on address 0x50c00000083e
READ of size 4 at 0x50c00000083e thread T0
    #0 in gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0+0xacf9c)
    #1 in try_load
    #2 in pixdata_image_load_increment
    #3 in generic_load_incrementally
    #4 in _gdk_pixbuf_generic_image_load
    #5 in gdk_pixbuf_new_from_file

0x50c000000840 is located 0 bytes to the right of 128-byte region
[0x50c0000007c0, 0x50c000000840)
allocated by thread T0 here:
    #0 in __interceptor_realloc
    #1 in g_realloc
    #2 in generic_load_incrementally
```

The OOB read occurs at `0x50c00000083e`, which is 2 bytes before the end of the 128-byte heap buffer (`0x50c000000840`). A 4-byte read starting there crosses the allocation boundary by 2 bytes, triggering the ASAN error.

The 128-byte buffer is the incremental file-loading chunk managed by `generic_load_incrementally`; the 29-byte input file fits within it. After the 5 bytes of pixel_data are consumed, `rle_buffer` sits at byte 29 within the chunk. The decoder continues looping because the output is not yet full, leading to reads from bytes 29-128+ of the chunk (heap content beyond the input data).

## Impact

- Allows reading up to approximately 40,000 iterations of out-of-bounds heap bytes before the output buffer fills or a crash occurs.
- Heap content adjacent to the pixel_data allocation may be leaked (information disclosure).
- On hardened systems the ASAN `unknown-crash` classification is consistent with a read from a heap redzone, indicating the read immediately follows the end of the live allocation.
- Exploitable for information disclosure; may contribute to ASLR bypass if combined with other vulnerabilities.

## Files

- `vuln_002_gen.py` - Generates `vuln_002.gdkp`
- `vuln_002_run.sh` - Runs the PoC with ASAN logging
- `vuln_002.gdkp` - Crafted input file (29 bytes)
- `vuln_002_result.txt` - Full stdout + ASAN log from test run
- `asan_002.log.*` - Raw ASAN log file(s)
- `vuln_002_status.txt` - Status: VERIFIED_CRASH
- `vuln_002_notes.md` - This file
